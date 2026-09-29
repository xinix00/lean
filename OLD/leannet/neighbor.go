package leannet

import "time"

// Timing values use monotonic nanoseconds. ARP and NDP deliberately share one
// small neighbor lifecycle instead of carrying separate reachability machines.
const (
	neighborEntryTTL   = int64(120 * time.Second)
	neighborRetryIval  = int64(time.Second)
	neighborQueryTries = 5
	neighborFailTTL    = int64(5 * time.Second)
)

type neighborState uint8

const (
	neighborPending  neighborState = iota // query active; MAC unknown
	neighborResolved                      // MAC known until born+neighborEntryTTL
	neighborFailed                        // negative cache until born+neighborFailTTL
)

type neighborEntry struct {
	mac    [6]byte
	state  neighborState
	static bool  // seeded entries never expire or refresh
	born   int64 // resolution refresh or failure time
	tries  int   // queries sent while pending
	due    int64 // next query time while pending
}

// neighborTable owns the lifecycle shared by ARP and NDP. Wire parsing,
// replies, router state, address policy, and public counters remain with the
// protocol tables; this type only makes expiry, capacity, learning, probing,
// and failure one compiler-checked implementation.
type neighborTable[K comparable] struct {
	entries map[K]*neighborEntry
	limit   int
}

func newNeighborTable[K comparable](limit int) neighborTable[K] {
	return neighborTable[K]{entries: make(map[K]*neighborEntry), limit: limit}
}

// tick expires resolved and failed entries. Pending failure belongs only to
// poll, which is called from the pump where the protocol can wake waiters.
func (t *neighborTable[K]) tick(key K, e *neighborEntry, now int64) bool {
	switch e.state {
	case neighborPending:
	case neighborResolved:
		if !e.static && now-e.born >= neighborEntryTTL {
			delete(t.entries, key)
			return false
		}
	case neighborFailed:
		if now-e.born >= neighborFailTTL {
			delete(t.entries, key)
			return false
		}
	}
	return true
}

// resolve returns a known MAC or starts one deduplicated query. refused means
// that pending/static work filled the table and no query could be installed.
func (t *neighborTable[K]) resolve(key K, now int64) (mac [6]byte, ok, refused bool) {
	if e, exists := t.entries[key]; exists && t.tick(key, e, now) {
		if e.state == neighborResolved {
			return e.mac, true, false
		}
		return mac, false, false
	}
	if !t.makeRoom(now) {
		return mac, false, true
	}
	t.entries[key] = &neighborEntry{state: neighborPending, due: now}
	return mac, false, false
}

// makeRoom expires and evicts entries until a new entry fits. It loops because
// static configuration can leave a table above its nominal limit.
func (t *neighborTable[K]) makeRoom(now int64) bool {
	if len(t.entries) < t.limit {
		return true
	}
	t.sweepExpired(now)
	for len(t.entries) >= t.limit {
		if !t.evictResolved() {
			return false
		}
	}
	return true
}

func (t *neighborTable[K]) sweepExpired(now int64) {
	for key, e := range t.entries {
		t.tick(key, e, now)
	}
}

// evictResolved removes one non-static answer. Pending work and static
// configuration are never evicted; a real peer can be relearned later.
func (t *neighborTable[K]) evictResolved() bool {
	for key, e := range t.entries {
		if e.state == neighborResolved && !e.static {
			delete(t.entries, key)
			return true
		}
	}
	return false
}

// peek returns a known MAC without starting a query.
func (t *neighborTable[K]) peek(key K, now int64) (mac [6]byte, ok bool) {
	if e, exists := t.entries[key]; exists && t.tick(key, e, now) && e.state == neighborResolved {
		return e.mac, true
	}
	return mac, false
}

// noAnswer reports a negative-cache hit or a table that cannot admit the
// missing query. It is the exact refusal mirror of makeRoom.
func (t *neighborTable[K]) noAnswer(key K, now int64) bool {
	e, exists := t.entries[key]
	if !exists {
		return t.fullLocked(now)
	}
	return t.tick(key, e, now) && e.state == neighborFailed
}

func (t *neighborTable[K]) fullLocked(now int64) bool {
	if len(t.entries) < t.limit {
		return false
	}
	t.sweepExpired(now)
	evictable := 0
	for _, e := range t.entries {
		if e.state == neighborResolved && !e.static {
			evictable++
		}
	}
	return len(t.entries)-evictable >= t.limit
}

// learn records validated passive traffic. It never evicts and never changes
// the MAC of an already resolved entry. dropped reports the capacity refusal.
func (t *neighborTable[K]) learn(key K, mac [6]byte, now int64) (woke, dropped bool) {
	e, exists := t.entries[key]
	if !exists || !t.tick(key, e, now) {
		if len(t.entries) >= t.limit {
			t.sweepExpired(now)
			if len(t.entries) >= t.limit {
				return false, true
			}
		}
		t.entries[key] = &neighborEntry{mac: mac, state: neighborResolved, born: now}
		return false, false
	}
	switch {
	case e.state == neighborPending:
		e.state = neighborResolved
		e.mac = mac
		e.born = now
		return true, false
	case e.state == neighborResolved && !e.static && e.mac == mac:
		e.born = now
	}
	return false, false
}

// resolvePending applies a solicited wire answer only to an active query.
func (t *neighborTable[K]) resolvePending(key K, mac [6]byte, now int64) bool {
	e, exists := t.entries[key]
	if !exists || !t.tick(key, e, now) || e.state != neighborPending {
		return false
	}
	e.state = neighborResolved
	e.mac = mac
	e.born = now
	return true
}

// refresh updates one live, non-static resolved entry. The two results let the
// protocol distinguish an ignored announcement from a real refresh and count
// MAC changes without putting protocol counters in this generic table.
func (t *neighborTable[K]) refresh(key K, mac [6]byte, now int64) (refreshed, changed bool) {
	e, exists := t.entries[key]
	if !exists || !t.tick(key, e, now) || e.state != neighborResolved || e.static {
		return false, false
	}
	changed = e.mac != mac
	if changed {
		e.mac = mac
	}
	e.born = now
	return true, changed
}

// poll advances due pending work. It may give up multiple entries before
// returning one query for the protocol-specific emitter to serialize.
func (t *neighborTable[K]) poll(now int64) (key K, query bool, gaveUp int) {
	for key, e := range t.entries {
		if !t.tick(key, e, now) || e.state != neighborPending || now < e.due {
			continue
		}
		if e.tries >= neighborQueryTries {
			e.state = neighborFailed
			e.born = now
			gaveUp++
			continue
		}
		e.tries++
		e.due = now + neighborRetryIval
		return key, true, gaveUp
	}
	return key, false, gaveUp
}

func (t *neighborTable[K]) nextDeadline(add func(int64)) {
	for _, e := range t.entries {
		switch e.state {
		case neighborPending:
			add(e.due)
		case neighborFailed:
			add(e.born + neighborFailTTL)
		}
	}
}
