// Package leanrand provides the four forms of randomness a node needs: bytes,
// IDs, bounded numbers, and wait jitter. All use crypto/rand, leaving one source
// and no per-call choice.
//
// It replaces github.com/google/uuid, which added 3,793 symbol bytes and pulled
// database/sql/driver into the HopOS arm64 kernel for two calls, one truncated
// to eight characters (measured 2026-08-12). It also centralizes three common
// mistakes: impossible crypto/rand errors, modulo bias, and synchronized retry
// schedules. [Read] panics if the system source fails, [N] uses rejection
// sampling, and [Jitter] spreads retries.
//
// It has no custom generator, seed, reproducible production stream, or UUID
// format. Tests should supply deterministic randomness where needed.
package leanrand

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// alfabet is Crockford base32 without I, L, O, or U: five unbiased bits per
// character and no easily confused pairs.
const alfabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Read fills p with random bytes. It has no error result: crypto/rand fills p
// completely, and a broken system source must panic rather than yield a partial
// key buffer.
func Read(p []byte) {
	if _, err := rand.Read(p); err != nil {
		panic("leanrand: the system random source failed: " + err.Error())
	}
}

// Bytes returns n random bytes. It returns an empty slice when n <= 0.
func Bytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	Read(b)
	return b
}

// Uint64 returns a random uint64 over the full range.
func Uint64() uint64 {
	var b [8]byte
	Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// N returns an unbiased random number in [0, n), including when n is not a
// power of two. It returns 0 for n == 0 so a zero length remains valid.
// Rejection sampling needs fewer than two draws on average, even when n is just
// above 2⁶³.
func N(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	// grens is the largest complete multiple of n representable by uint64.
	grens := ^uint64(0) - (^uint64(0)%n+1)%n
	for {
		v := Uint64()
		if v <= grens {
			return v % n
		}
	}
}

// Hex returns 2n lowercase hexadecimal characters from n random bytes.
func Hex(n int) string {
	const digits = "0123456789abcdef"
	b := Bytes(n)
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// ID returns an n-character identifier from [alfabet], with five bits per
// character. Twelve characters provide 60 bits and sixteen provide 80. It
// returns "" when n <= 0.
func ID(n int) string {
	if n <= 0 {
		return ""
	}
	b := Bytes(n)
	for i, c := range b {
		b[i] = alfabet[c&31] // 32 divides 256, so this is unbiased.
	}
	return string(b)
}

// Jitter spreads d by ±50%, returning a duration in [d/2, 3d/2). This avoids
// synchronized backoff and periodic work. Non-positive durations are unchanged.
func Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(N(uint64(d)))
}
