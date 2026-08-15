package leannet

// arp.go implements the Ethernet/IPv4 ARP machine (RFC 826). It has no
// goroutines or clock: callers pass monotonic nanoseconds to resolve, recv, and
// emit. The stack pumps packets and polls resolve until it gets a MAC or
// noAnswer reports an explicit failure.
//
// Polling avoids callback lifecycle state; an earlier implementation repeatedly
// fired stale callbacks on later gratuitous replies.
//
// The table is not internally locked; the stack lock covers every operation.

import "time"

// Timing values use monotonic nanoseconds.
const (
	arpEntryTTL   = int64(120 * time.Second) // resolved-entry lifetime
	arpRetryIval  = int64(time.Second)       // interval between queries
	arpQueryTries = 5                        // attempts before explicit failure

	// Keep a failed query briefly so waiters observe the failure and dead hosts
	// are not queried continuously.
	arpFailTTL = int64(5 * time.Second)

	// Bound queued replies so a request flood cannot grow memory indefinitely.
	arpReplyQueueCap = 8

	// Bound passive learning so spoofed source IPs cannot grow the map into a
	// memory DoS. Real nodes use far fewer than 128 peers.
	arpCacheCap = 128
)

// arpState represents an entry's lifecycle.
type arpState uint8

const (
	arpPending  arpState = iota // query active; MAC unknown
	arpResolved                 // MAC known until born+arpEntryTTL
	arpFailed                   // negative cache until born+arpFailTTL
)

// arpEntry stores one IP's state.
type arpEntry struct {
	mac    [6]byte
	state  arpState
	static bool  // seeded entries never expire or refresh
	born   int64 // resolution refresh or failure time
	tries  int   // queries sent while pending
	due    int64 // next query time while pending
}

// arpReply is a queued response to a request for our IP.
type arpReply struct {
	hw [6]byte
	ip [4]byte
}

// arpTable maps IPv4 addresses to MACs and drives queries.
type arpTable struct {
	ourIP  [4]byte
	ourMAC [6]byte

	// The map key enforces one entry per IP, deduplicating concurrent resolvers.
	entries map[[4]byte]*arpEntry

	// emit drains replies to requests for our IP.
	replies []arpReply

	// Stats copies this block for telemetry; the machine itself does not log.
	cnt ARPStats
}

func newARPTable(ourIP [4]byte, ourMAC [6]byte) *arpTable {
	return &arpTable{ourIP: ourIP, ourMAC: ourMAC, entries: make(map[[4]byte]*arpEntry)}
}

// tick expires resolved and failed entries. Pending failure belongs exclusively
// to emit because that pump also wakes waiters.
func (t *arpTable) tick(ip [4]byte, e *arpEntry, now int64) bool {
	switch e.state {
	case arpPending:
		// Do not transition here: only emit runs inside drainLocked's GaveUp
		// delta notification, which guarantees even deadline-free waiters wake.
	case arpResolved:
		if !e.static && now-e.born >= arpEntryTTL {
			delete(t.entries, ip)
			return false
		}
	case arpFailed:
		if now-e.born >= arpFailTTL {
			delete(t.entries, ip)
			return false
		}
	}
	return true
}

// resolve returns a known MAC or starts one deduplicated query for ip. Failed
// queries remain negative-cached briefly; waiters use noAnswer to fail.
func (t *arpTable) resolve(ip [4]byte, now int64) (mac [6]byte, ok bool) {
	if e, exists := t.entries[ip]; exists && t.tick(ip, e, now) {
		if e.state == arpResolved {
			return e.mac, true
		}
		return mac, false // pending or failed; do not start another query
	}
	// Active resolution takes precedence over unrequested cached answers, but
	// remains capped because external traffic can trigger it.
	if !t.makeRoom(now) {
		// A table full of pending/static entries cannot start a query. noAnswer
		// reports this explicitly so callers do not sleep forever.
		t.cnt.FullDrop++
		return mac, false
	}
	t.entries[ip] = &arpEntry{state: arpPending, due: now}
	return mac, false
}

// makeRoom expires and evicts entries until below the cap. It must loop because
// seeded configurations can leave the table above the cap.
func (t *arpTable) makeRoom(now int64) bool {
	if len(t.entries) < arpCacheCap {
		return true
	}
	t.sweepExpired(now)
	for len(t.entries) >= arpCacheCap {
		if !t.evictResolved() {
			return false
		}
	}
	return true
}

// sweepExpired removes expired entries before eviction or refusal.
func (t *arpTable) sweepExpired(now int64) {
	for ip, e := range t.entries {
		t.tick(ip, e, now)
	}
}

// evictResolved removes any non-static resolved entry. Pending work and static
// configuration are not evictable; a real peer can be relearned on its next packet.
func (t *arpTable) evictResolved() bool {
	for ip, e := range t.entries {
		if e.state == arpResolved && !e.static {
			delete(t.entries, ip)
			return true
		}
	}
	return false
}

// peek returns a known MAC without starting a query. Best-effort replies use it
// so spoofed sources cannot turn each refused packet into a pending query.
func (t *arpTable) peek(ip [4]byte, now int64) (mac [6]byte, ok bool) {
	if e, exists := t.entries[ip]; exists && t.tick(ip, e, now) && e.state == arpResolved {
		return e.mac, true
	}
	return mac, false
}

// noAnswer reports query failure. The negative cache expires after arpFailTTL.
//
// A missing entry also fails when non-evictable work fills the table, because
// resolve could not create a query or a later arpFailed entry.
func (t *arpTable) noAnswer(ip [4]byte, now int64) bool {
	e, exists := t.entries[ip]
	if !exists {
		return t.fullLocked(now)
	}
	return t.tick(ip, e, now) && e.state == arpFailed
}

// fullLocked mirrors makeRoom failure: after expiry, non-evictable entries fill
// the cap. Counting matters when seeded configuration puts the table over cap.
func (t *arpTable) fullLocked(now int64) bool {
	if len(t.entries) < arpCacheCap {
		return false
	}
	t.sweepExpired(now)
	evictable := 0
	for _, e := range t.entries {
		if e.state == arpResolved && !e.static {
			evictable++
		}
	}
	return len(t.entries)-evictable >= arpCacheCap
}

// seed installs a static, non-expiring entry, replacing any previous state.
// wokePending tells the stack to wake waiters whose query and timer vanished.
//
// The stack must reject off-subnet seeds; this table does not know the subnet.
func (t *arpTable) seed(ip [4]byte, mac [6]byte) (wokePending bool) {
	old, exists := t.entries[ip]
	t.entries[ip] = &arpEntry{mac: mac, state: arpResolved, static: true}
	return exists && old.state == arpPending
}

// learn passively records unicast IPv4 sources addressed to us. It may create
// or refresh an entry but never change an existing MAC; that requires ARP recv,
// preventing spoofed data frames from redirecting an established gateway entry.
//
// wokePending tells the stack to notify a waiter even if later packet handling
// returns early.
func (t *arpTable) learn(ip [4]byte, mac [6]byte, now int64) (wokePending bool) {
	if ip == t.ourIP {
		return false
	}
	e, exists := t.entries[ip]
	if !exists || !t.tick(ip, e, now) {
		// Passive learning never evicts. A real peer merely loses the shortcut
		// and can still resolve through ARP.
		if len(t.entries) >= arpCacheCap {
			t.sweepExpired(now)
			if len(t.entries) >= arpCacheCap {
				t.cnt.LearnDrop++
				return false
			}
		}
		t.entries[ip] = &arpEntry{mac: mac, state: arpResolved, born: now}
		return false
	}
	switch {
	case e.state == arpPending:
		// Data traffic arrived before or instead of the ARP reply.
		e.state = arpResolved
		e.mac = mac
		e.born = now
		return true
	case e.state == arpResolved && !e.static && e.mac == mac:
		e.born = now // same MAC: refresh only the TTL
	}
	return false
}

// recv processes a validated ARP payload. Only a reply addressed to us for a
// pending query may create resolution state. Requests, gratuitous announcements,
// and third-party traffic can only refresh an existing resolved entry.
func (t *arpTable) recv(f ARPFrame, now int64) {
	sender := [4]byte(f.SenderProto())
	target := [4]byte(f.TargetProto())
	var senderHW [6]byte
	copy(senderHW[:], f.SenderHW())

	switch f.Op() {
	case ARPRequest:
		// Queue a response when the peer asks for our address.
		if target == t.ourIP && sender != t.ourIP {
			if len(t.replies) >= arpReplyQueueCap {
				t.cnt.ReplyDrop++
			} else {
				t.replies = append(t.replies, arpReply{hw: senderHW, ip: sender})
			}
		}
		// Request sender data may only refresh an existing entry; it cannot
		// resolve a pending query.
		t.refresh(sender, senderHW, now)
	case ARPReply:
		switch {
		case target == t.ourIP:
			// A reply to us resolves a pending query or refreshes an entry.
			if e, exists := t.entries[sender]; exists && t.tick(sender, e, now) && e.state == arpPending {
				e.state = arpResolved
				e.mac = senderHW
				e.born = now
				return
			}
			t.refresh(sender, senderHW, now)
		case target == sender:
			// Gratuitous replies refresh but never create entries. Count MAC
			// changes for stack-level logging.
			t.refresh(sender, senderHW, now)
		default:
			// Ignore replies for someone else's exchange; accepting them enables
			// broadcast ARP poisoning.
			t.cnt.Ignored++
		}
	}
}

// refresh updates an existing non-static resolved entry; it never creates one.
func (t *arpTable) refresh(ip [4]byte, mac [6]byte, now int64) {
	e, exists := t.entries[ip]
	if !exists || !t.tick(ip, e, now) || e.state != arpResolved || e.static {
		return
	}
	if e.mac != mac {
		t.cnt.MACChanged++
		e.mac = mac
	}
	e.born = now
}

// emit writes one queued reply or due query. The caller loops until false and
// wraps replies in unicast Ethernet and requests in broadcast Ethernet. A short
// buffer is a caller-accounting bug and panics.
func (t *arpTable) emit(buf []byte, now int64) (n int, ok bool) {
	if len(t.replies) > 0 {
		r := t.replies[0]
		copy(t.replies, t.replies[1:])
		t.replies = t.replies[:len(t.replies)-1]
		return t.putARP(buf, ARPReply, r.hw, r.ip)
	}
	for ip, e := range t.entries {
		if !t.tick(ip, e, now) || e.state != arpPending || now < e.due {
			continue
		}
		if e.tries >= arpQueryTries {
			// Fail only here so drainLocked's GaveUp delta wakes every waiter.
			e.state = arpFailed
			e.born = now
			t.cnt.GaveUp++
			continue
		}
		e.tries++
		e.due = now + arpRetryIval
		return t.putARP(buf, ARPRequest, [6]byte{}, ip)
	}
	return 0, false
}

// putARP writes a packet whose sender is always this host.
func (t *arpTable) putARP(buf []byte, op uint16, targetHW [6]byte, targetIP [4]byte) (int, bool) {
	n, err := PutARP(buf, op, t.ourMAC, t.ourIP, targetHW, targetIP)
	if err != nil {
		panic("leannet: arp emit buffer too small")
	}
	return n, true
}
