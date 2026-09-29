package leannet

// Congestion control applies to physical routes only. Trusted memory links keep
// their receive-window-only fast path. Existing ACKs and RTO drive all state;
// there is no pacing worker, timer, or additional synchronization.
const maxCongestionWindow = 1 << 30

func (c *tcpConn) initCongestion() {
	if !c.congestion {
		return
	}
	// RFC 6928 initial window, using the negotiated sender MSS.
	c.cwnd = c.initialCongestionWindow()
	c.ssthresh = maxCongestionWindow
	c.cwndAcked = 0
}

func (c *tcpConn) congestionACK(acked int) {
	if !c.congestion || acked <= 0 {
		return
	}
	if c.cwnd < c.ssthresh {
		// RFC 5681 slow start: at most one MSS per ACK, even a cumulative ACK.
		c.cwnd = min(maxCongestionWindow, c.cwnd+min(acked, c.peerMSS))
		return
	}
	// Congestion avoidance: one MSS per window of newly acknowledged bytes.
	c.cwndAcked += acked
	if c.cwndAcked >= c.cwnd {
		c.cwndAcked -= c.cwnd
		c.cwnd = min(maxCongestionWindow, c.cwnd+c.peerMSS)
	}
}

func (c *tcpConn) congestionLoss() {
	if !c.congestion {
		return
	}
	// FlightSize must not shrink merely because the retransmission cursor rewinds.
	c.ssthresh = max(seqDiff(c.maxSent, c.una)/2, 2*c.peerMSS)
	// Conservative Tahoe recovery; partial ACKs clock the remaining replay.
	c.cwnd = c.peerMSS
	c.cwndAcked = 0
}

func (c *tcpConn) congestionAvailable() int {
	if !c.congestion {
		return maxCongestionWindow
	}
	if seqLT(c.nxt, c.maxSent) {
		// A reduced window still permits recovery of already-sent bytes, but not
		// a complete go-back-N burst. Each advancing ACK admits the next replay.
		return max(0, min(c.cwnd-seqDiff(c.nxt, c.una), seqDiff(c.maxSent, c.nxt)))
	}
	return max(0, c.cwnd-seqDiff(c.maxSent, c.una))
}

func (c *tcpConn) initialCongestionWindow() int {
	return min(10*c.peerMSS, max(2*c.peerMSS, 14600))
}

// An idle connection restarts conservatively without another timer. Outstanding
// data retains its recovery window; only fully acknowledged flights restart.
func (c *tcpConn) restartCongestionAfterIdle(now int64) {
	if c.congestion && c.tx.unsent() > 0 && c.maxSent == c.una && c.lastDataSent != 0 && now-c.lastDataSent >= int64(c.currentRTO()) {
		c.cwnd = min(c.cwnd, c.initialCongestionWindow())
		c.cwndAcked = 0
	}
}
