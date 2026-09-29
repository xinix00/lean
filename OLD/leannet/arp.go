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

const (
	// Bound queued replies so a request flood cannot grow memory indefinitely.
	arpReplyQueueCap = 8

	// Bound passive learning so spoofed source IPs cannot grow the map into a
	// memory DoS. Real nodes use far fewer than 128 peers.
	arpCacheCap = 128
)

// arpReply is a queued response to a request for our IP.
type arpReply struct {
	hw [6]byte
	ip [4]byte
}

// arpTable maps IPv4 addresses to MACs and drives queries.
type arpTable struct {
	neighborTable[[4]byte]

	ourIP  [4]byte
	ourMAC [6]byte

	// emit drains replies to requests for our IP.
	replies []arpReply

	// Stats copies this block for telemetry; the machine itself does not log.
	cnt ARPStats
}

func newARPTable(ourIP [4]byte, ourMAC [6]byte) *arpTable {
	return &arpTable{
		neighborTable: newNeighborTable[[4]byte](arpCacheCap),
		ourIP:         ourIP,
		ourMAC:        ourMAC,
	}
}

// resolve returns a known MAC or starts one deduplicated query for ip. Failed
// queries remain negative-cached briefly; waiters use noAnswer to fail.
func (t *arpTable) resolve(ip [4]byte, now int64) (mac [6]byte, ok bool) {
	mac, ok, refused := t.neighborTable.resolve(ip, now)
	if refused {
		t.cnt.FullDrop++
	}
	return mac, ok
}

// seed installs a static, non-expiring entry, replacing any previous state.
// wokePending tells the stack to wake waiters whose query and timer vanished.
//
// The stack must reject off-subnet seeds; this table does not know the subnet.
func (t *arpTable) seed(ip [4]byte, mac [6]byte) (wokePending bool) {
	old, exists := t.entries[ip]
	t.entries[ip] = &neighborEntry{mac: mac, state: neighborResolved, static: true}
	return exists && old.state == neighborPending
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
	woke, dropped := t.neighborTable.learn(ip, mac, now)
	if dropped {
		t.cnt.LearnDrop++
	}
	return woke
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
			if t.resolvePending(sender, senderHW, now) {
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
	_, changed := t.neighborTable.refresh(ip, mac, now)
	if changed {
		t.cnt.MACChanged++
	}
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
	ip, query, gaveUp := t.poll(now)
	t.cnt.GaveUp += gaveUp
	if query {
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
