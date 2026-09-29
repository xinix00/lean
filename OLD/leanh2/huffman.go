package leanh2

import "sync"

// The Huffman decoder walks bit by bit through a tree built once from the code
// table. That is deliberately not the fastest shape — the standard library uses
// a table per four bits — but it is the smallest one that is provably right: the
// tree cannot miss a code that is in the table, and there is no second
// representation of the same data to drift out of step.
//
// Headers are tens of bytes per request; what a faster decoder would win
// disappears next to a single TLS record.
type huffNode struct {
	kids [2]int32 // index in de boom, of -1
	sym  int16    // symbool op een blad, anders -1
}

var (
	huffOnce sync.Once
	huffTree []huffNode
)

func buildHuffTree() {
	huffTree = []huffNode{{kids: [2]int32{-1, -1}, sym: -1}}
	for sym := 0; sym < 256; sym++ {
		code, bits := huffCode[sym], int(huffBits[sym])
		node := int32(0)
		for i := bits - 1; i >= 0; i-- {
			b := (code >> uint(i)) & 1
			next := huffTree[node].kids[b]
			if next == -1 {
				huffTree = append(huffTree, huffNode{kids: [2]int32{-1, -1}, sym: -1})
				next = int32(len(huffTree) - 1)
				huffTree[node].kids[b] = next
			}
			node = next
		}
		huffTree[node].sym = int16(sym)
	}
}

// huffmanDecode decodes a Huffman-coded string literal.
//
// Two things RFC 7541 §5.2 requires and a naive loop skips: EOS may not appear
// in the stream, and the tail may only be padding — at most seven bits, all
// ones (the start of the EOS code). Anything else is an error rather than
// something to round off quietly; otherwise this accepts bytes another
// implementation would refuse.
func huffmanDecode(src []byte) (string, error) {
	huffOnce.Do(buildHuffTree)

	out := make([]byte, 0, len(src)*8/5)
	node := int32(0)
	depth := 0
	ones := true
	for _, b := range src {
		for i := 7; i >= 0; i-- {
			bit := (b >> uint(i)) & 1
			if bit == 0 {
				ones = false
			}
			next := huffTree[node].kids[bit]
			if next == -1 {
				// Cannot happen: the tree covers every code in the table, and
				// every path through it ends on a leaf or continues. A gap would
				// mean a broken table, not broken input.
				return "", errEOS
			}
			node = next
			depth++
			if sym := huffTree[node].sym; sym >= 0 {
				out = append(out, byte(sym))
				node = 0
				depth = 0
				ones = true
			}
		}
	}
	if depth > 7 || !ones {
		// A partial code longer than the padding allowance, or padding with a
		// zero in it: both are decoding errors.
		return "", errEOS
	}
	return string(out), nil
}
