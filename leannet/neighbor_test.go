package leannet

import "testing"

func TestNeighborLifecycleIsSharedByAddressFamily(t *testing.T) {
	t.Run("IPv4 key", func(t *testing.T) {
		testNeighborLifecycle(t, [][4]byte{{1}, {2}, {3}, {4}, {5}})
	})
	t.Run("IPv6 key", func(t *testing.T) {
		testNeighborLifecycle(t, [][16]byte{{1}, {2}, {3}, {4}, {5}})
	})
}

func testNeighborLifecycle[K comparable](t *testing.T, keys []K) {
	t.Helper()
	tab := newNeighborTable[K](3)
	mac := [6]byte{2, 0, 0, 0, 0, 1}

	if _, ok, refused := tab.resolve(keys[0], 0); ok || refused || len(tab.entries) != 1 {
		t.Fatalf("first resolve = ok=%v refused=%v entries=%d", ok, refused, len(tab.entries))
	}
	if _, ok, refused := tab.resolve(keys[0], 0); ok || refused || len(tab.entries) != 1 {
		t.Fatalf("deduplicated resolve = ok=%v refused=%v entries=%d", ok, refused, len(tab.entries))
	}
	if woke, dropped := tab.learn(keys[0], mac, 1); !woke || dropped {
		t.Fatalf("learn pending = woke=%v dropped=%v", woke, dropped)
	}
	if got, ok := tab.peek(keys[0], 1); !ok || got != mac {
		t.Fatalf("peek learned = (%v, %v), want (%v, true)", got, ok, mac)
	}

	now := int64(10)
	if _, _, refused := tab.resolve(keys[1], now); refused {
		t.Fatal("second query was refused")
	}
	for try := 0; try < neighborQueryTries; try++ {
		key, query, gaveUp := tab.poll(now)
		if !query || key != keys[1] || gaveUp != 0 {
			t.Fatalf("poll %d = key=%v query=%v gaveUp=%d", try, key, query, gaveUp)
		}
		now += neighborRetryIval
	}
	if _, query, gaveUp := tab.poll(now); query || gaveUp != 1 {
		t.Fatalf("give-up poll = query=%v gaveUp=%d", query, gaveUp)
	}
	if !tab.noAnswer(keys[1], now) {
		t.Fatal("failed query was not negative-cached")
	}
	if _, ok, refused := tab.resolve(keys[1], now+neighborFailTTL); ok || refused {
		t.Fatalf("expired failure did not restart: ok=%v refused=%v", ok, refused)
	}
	if e := tab.entries[keys[1]]; e == nil || e.state != neighborPending || e.due != now+neighborFailTTL {
		t.Fatalf("expired failure restarted as %#v, want a fresh pending query", e)
	}

	// An over-cap table needs more than one eviction before a new key fits.
	tab = newNeighborTable[K](3)
	tab.entries[keys[0]] = &neighborEntry{state: neighborResolved}
	tab.entries[keys[1]] = &neighborEntry{state: neighborResolved}
	tab.entries[keys[2]] = &neighborEntry{state: neighborPending}
	tab.entries[keys[3]] = &neighborEntry{state: neighborPending}
	if !tab.makeRoom(0) || len(tab.entries) != 2 {
		t.Fatalf("multi-eviction left %d entries", len(tab.entries))
	}
	tab.entries[keys[4]] = &neighborEntry{state: neighborPending}
	if !tab.fullLocked(0) || !tab.noAnswer(keys[0], 0) {
		t.Fatal("non-evictable capacity did not fail loudly")
	}
}

func TestNeighborWrappersKeepTheirLifecycleAccounting(t *testing.T) {
	arp := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	ndp := newNDPTable([6]byte{2, 0, 0, 0, 0, 1}, 0)
	if arp.limit != arpCacheCap || ndp.limit != ndpCacheCap {
		t.Fatalf("neighbor limits: ARP=%d NDP=%d", arp.limit, ndp.limit)
	}

	for i := 0; i < ndpCacheCap; i++ {
		key := [16]byte{14: byte(i >> 8), 15: byte(i)}
		ndp.entries[key] = &neighborEntry{state: neighborPending, due: 1}
	}
	missing := [16]byte{14: 1}
	if _, ok := ndp.resolve(missing, 0); ok || ndp.cnt.FullDrop != 1 {
		t.Fatalf("full resolve: ok=%v full-drop=%d", ok, ndp.cnt.FullDrop)
	}
	if ndp.learn(missing, [6]byte{2, 0, 0, 0, 0, 2}, 0) || ndp.cnt.LearnDrop != 1 {
		t.Fatalf("full learn: learn-drop=%d", ndp.cnt.LearnDrop)
	}

	ndp = newNDPTable([6]byte{2, 0, 0, 0, 0, 1}, 0)
	failed := [16]byte{15: 1}
	ndp.entries[failed] = &neighborEntry{state: neighborPending, tries: neighborQueryTries}
	ndp.emit(make([]byte, 64), 0)
	if ndp.cnt.GaveUp != 1 {
		t.Fatalf("NDP give-up counter = %d, want 1", ndp.cnt.GaveUp)
	}
}
