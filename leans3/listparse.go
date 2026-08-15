package leans3

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ListObjectsV2 returns XML, but this package reads only three fields.
// encoding/xml added 39,344 symbol bytes to the HopOS arm64 kernel
// (2026-08-12) for a reflective general-purpose decoder.
//
// This parser makes one pass, matches local element names, and decodes the five
// predefined plus numeric entities. Unknown elements are skipped for forward
// compatibility; unsupported syntax fails loudly. It requires every opened tag
// and the root to close so a truncated page can never masquerade as a complete
// listing with fewer keys.

// maxDepth bounds nesting. Valid pages need depth three; this headroom turns
// malicious open-tag streams into errors rather than unbounded slices.
const maxDepth = 32

// parseListPage reads the fields needed by [Client.List]. It matches local name
// and position: IsTruncated and NextContinuationToken under the root, and Key
// under Contents. Same-named extension fields cannot alter the result.
func parseListPage(b []byte) (*listBucketResult, error) {
	var (
		out   listBucketResult
		stack = make([]string, 0, 8)
		// Collect text only for wanted fields; discard extension content eagerly.
		text  []byte
		wil   bool
		zag   bool // root opened
		klaar bool // root closed
	)

	i := 0
	for i < len(b) {
		c := b[i]
		if c != '<' {
			j := indexByteFrom(b, i, '<')
			if j < 0 {
				j = len(b)
			}
			if wil {
				text = append(text, b[i:j]...)
			}
			i = j
			continue
		}

		switch {
		case heeft(b, i, "<?"): // <?xml ... ?>
			e := index(b, i, "?>")
			if e < 0 {
				return nil, errors.New("leans3: unterminated XML declaration")
			}
			i = e + 2

		case heeft(b, i, "<!--"):
			e := index(b, i, "-->")
			if e < 0 {
				return nil, errors.New("leans3: unterminated XML comment")
			}
			i = e + 3

		case heeft(b, i, "<![CDATA["):
			e := index(b, i, "]]>")
			if e < 0 {
				return nil, errors.New("leans3: unterminated CDATA section")
			}
			if wil {
				text = append(text, b[i+len("<![CDATA["):e]...)
			}
			i = e + 3

		case heeft(b, i, "<!"): // <!DOCTYPE ...>
			e := indexByteFrom(b, i, '>')
			if e < 0 {
				return nil, errors.New("leans3: unterminated markup declaration")
			}
			i = e + 1

		case heeft(b, i, "</"):
			naam, e, err := tagNaam(b, i+2)
			if err != nil {
				return nil, err
			}
			if len(stack) == 0 {
				return nil, fmt.Errorf("leans3: closing tag </%s> without an open element", naam)
			}
			if top := stack[len(stack)-1]; top != naam {
				return nil, fmt.Errorf("leans3: closing tag </%s> does not match <%s>", naam, top)
			}
			if wil {
				s, err := unescape(text)
				if err != nil {
					return nil, err
				}
				if err := zet(&out, stack, s); err != nil {
					return nil, err
				}
			}
			stack = stack[:len(stack)-1]
			text, wil = text[:0], false
			if len(stack) == 0 {
				klaar = true
			}
			i = e

		default:
			naam, e, zelfsluitend, err := startTag(b, i)
			if err != nil {
				return nil, err
			}
			if klaar {
				return nil, errors.New("leans3: content after the root element")
			}
			if len(stack) == 0 {
				zag = true
			}
			if len(stack) == maxDepth {
				return nil, fmt.Errorf("leans3: XML nested deeper than %d elements", maxDepth)
			}
			stack = append(stack, naam)
			if zelfsluitend {
				// Treat a self-closing wanted field as an empty value.
				if wilVeld(stack) {
					if err := zet(&out, stack, ""); err != nil {
						return nil, err
					}
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					klaar = true
				}
				i = e
				continue
			}
			text, wil = text[:0], wilVeld(stack)
			i = e
		}
	}

	if len(stack) != 0 {
		return nil, fmt.Errorf("leans3: truncated XML: <%s> was never closed", stack[len(stack)-1])
	}
	if !zag || !klaar {
		return nil, errors.New("leans3: no complete XML element in the response")
	}
	return &out, nil
}

// wilVeld reports whether stack identifies a wanted field. The root name stays
// unrestricted because not every S3 implementation uses ListBucketResult.
func wilVeld(stack []string) bool {
	switch len(stack) {
	case 2:
		return stack[1] == "IsTruncated" || stack[1] == "NextContinuationToken"
	case 3:
		return stack[1] == "Contents" && stack[2] == "Key"
	}
	return false
}

// zet stores a parsed field. Invalid IsTruncated is an error because uncertain
// pagination cannot be treated as complete.
func zet(out *listBucketResult, stack []string, waarde string) error {
	switch {
	case len(stack) == 2 && stack[1] == "IsTruncated":
		switch strings.TrimSpace(waarde) {
		case "true", "1":
			out.IsTruncated = true
		case "false", "0", "":
			out.IsTruncated = false
		default:
			return fmt.Errorf("leans3: IsTruncated is %q, not a boolean", waarde)
		}
	case len(stack) == 2 && stack[1] == "NextContinuationToken":
		out.NextContinuationToken = waarde
	case len(stack) == 3:
		out.Contents = append(out.Contents, listEntry{Key: waarde})
	}
	return nil
}

// startTag reads a start tag and returns its local name, end index, and
// self-closing flag. Quoted `>` bytes do not end attributes.
func startTag(b []byte, i int) (naam string, eind int, zelfsluitend bool, err error) {
	naam, j, err := tagNaamOpen(b, i+1)
	if err != nil {
		return "", 0, false, err
	}
	for j < len(b) {
		switch b[j] {
		case '"', '\'':
			q := b[j]
			k := indexByteFrom(b, j+1, q)
			if k < 0 {
				return "", 0, false, fmt.Errorf("leans3: unterminated attribute value in <%s>", naam)
			}
			j = k + 1
		case '/':
			if j+1 < len(b) && b[j+1] == '>' {
				return naam, j + 2, true, nil
			}
			j++
		case '>':
			return naam, j + 1, false, nil
		default:
			j++
		}
	}
	return "", 0, false, fmt.Errorf("leans3: unterminated tag <%s", naam)
}

// tagNaam reads a closing-tag name and returns the index after `>`.
func tagNaam(b []byte, i int) (naam string, eind int, err error) {
	naam, j, err := tagNaamOpen(b, i)
	if err != nil {
		return "", 0, err
	}
	for j < len(b) && b[j] != '>' {
		if !ruimte(b[j]) {
			return "", 0, fmt.Errorf("leans3: junk in closing tag </%s", naam)
		}
		j++
	}
	if j == len(b) {
		return "", 0, fmt.Errorf("leans3: unterminated closing tag </%s", naam)
	}
	return naam, j + 1, nil
}

// tagNaamOpen reads an element name and returns the local part after the final
// namespace colon.
func tagNaamOpen(b []byte, i int) (naam string, eind int, err error) {
	start := i
	for i < len(b) && !ruimte(b[i]) && b[i] != '>' && b[i] != '/' {
		i++
	}
	if i == start {
		return "", 0, errors.New("leans3: empty XML tag name")
	}
	n := b[start:i]
	if k := lastIndexByte(n, ':'); k >= 0 {
		n = n[k+1:]
	}
	if len(n) == 0 {
		return "", 0, errors.New("leans3: XML tag name is only a namespace prefix")
	}
	return string(n), i, nil
}

// unescape decodes the five predefined entities and numeric references. Unknown
// entities fail instead of silently corrupting object keys.
func unescape(b []byte) (string, error) {
	if indexByteFrom(b, 0, '&') < 0 {
		return string(b), nil // Common case: no entity work.
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != '&' {
			out = append(out, b[i])
			i++
			continue
		}
		e := indexByteFrom(b, i, ';')
		if e < 0 || e-i > 12 { // "&#x10FFFF;" is the longest supported form.
			return "", errors.New("leans3: unterminated XML entity")
		}
		ent := string(b[i+1 : e])
		switch ent {
		case "amp":
			out = append(out, '&')
		case "lt":
			out = append(out, '<')
		case "gt":
			out = append(out, '>')
		case "quot":
			out = append(out, '"')
		case "apos":
			out = append(out, '\'')
		default:
			if len(ent) < 2 || ent[0] != '#' {
				return "", fmt.Errorf("leans3: unknown XML entity &%s;", ent)
			}
			cijfers, basis := ent[1:], 10
			if cijfers[0] == 'x' || cijfers[0] == 'X' {
				cijfers, basis = cijfers[1:], 16
			}
			v, err := strconv.ParseUint(cijfers, basis, 32)
			if err != nil {
				return "", fmt.Errorf("leans3: bad numeric XML entity &%s;", ent)
			}
			r := rune(v)
			if r > utf8.MaxRune || (r >= 0xd800 && r <= 0xdfff) {
				return "", fmt.Errorf("leans3: XML entity &%s; is not a character", ent)
			}
			out = utf8.AppendRune(out, r)
		}
		i = e + 1
	}
	return string(out), nil
}

func ruimte(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// Reports whether s begins at b[i].
func heeft(b []byte, i int, s string) bool {
	return len(b)-i >= len(s) && string(b[i:i+len(s)]) == s
}

// index finds s in b from i without converting the full response to a string.
func index(b []byte, i int, s string) int {
	for ; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return i
		}
	}
	return -1
}

func indexByteFrom(b []byte, i int, c byte) int {
	for ; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}
