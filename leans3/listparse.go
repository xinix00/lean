package leans3

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Het antwoord op een ListObjectsV2 is XML, en dit pakket leest er drie velden
// uit. Daarvoor stond hier encoding/xml: 39.344 bytes symbolen in de HopOS-kern
// (gemeten 12-08-2026, arm64) voor een reflectie-gedreven decoder met
// namespaces, naamruimte-prefixen en een compleet tokenmodel, om drie
// elementnamen te herkennen in een document dat S3 zelf genereert.
//
// Dus doet dit bestand precies dat: één keer over de bytes, elementnamen op
// hun lokale naam, tekst met de vijf XML-entiteiten (plus numerieke) eruit
// gehaald. Wat het níet kan, weigert het luid — met één uitzondering die
// bewust géén fout is: een element dat we niet zoeken wordt overgeslagen,
// inclusief zijn inhoud. Dat is wat een lijst-antwoord uitbreidbaar maakt.
//
// De gevaarlijke fout in zulke code is een afgekapt antwoord dat op een
// compleet antwoord lijkt: minder keys, IsTruncated afwezig, en de aanroeper
// die denkt dat de listing op is. Daarom eist de parser een document dat
// sluit: elke open tag dicht, en de wortel afgesloten. Een halve stream is een
// fout, net als bij encoding/xml.

// maxDepth begrenst de nesting. Een ListBucketResult komt tot drie diep
// (wortel → Contents → Key); dit is ruim, en het maakt van een document dat
// alleen uit open tags bestaat een fout in plaats van een groeiende slice.
const maxDepth = 32

// parseListPage leest de drie velden die [Client.List] nodig heeft uit een
// ListObjectsV2-antwoord.
//
// Matchen gaat op lokale naam (de namespace-prefix van een element telt niet
// mee) en op positie: IsTruncated en NextContinuationToken direct onder de
// wortel, Key direct onder Contents. Zo kan een veld met dezelfde naam ergens
// diep in een uitbreiding nooit stil het antwoord veranderen.
func parseListPage(b []byte) (*listBucketResult, error) {
	var (
		out   listBucketResult
		stack = make([]string, 0, 8)
		// text verzamelt de tekens van het element waar we in staan, maar
		// alleen als het een veld is dat we willen: al het andere gooien we
		// meteen weg.
		text  []byte
		wil   bool
		zag   bool // wortel geopend
		klaar bool // wortel gesloten
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
				// <IsTruncated/> is een leeg element: de waarde is de lege
				// string, en die moet door dezelfde toets als een echte.
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

// wilVeld zegt of het pad in stack een veld is dat we lezen. Twee niveaus
// onder de wortel, of Key onder Contents — de wortelnaam zelf laten we vrij,
// want niet elke S3-implementatie noemt hem ListBucketResult.
func wilVeld(stack []string) bool {
	switch len(stack) {
	case 2:
		return stack[1] == "IsTruncated" || stack[1] == "NextContinuationToken"
	case 3:
		return stack[1] == "Contents" && stack[2] == "Key"
	}
	return false
}

// zet legt de gelezen waarde op zijn plek. Een IsTruncated die geen boolean is
// is een fout: "misschien is de listing op" is geen antwoord.
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

// startTag leest <naam attr="..."> en geeft de lokale naam, de index ná de tag
// en of hij zichzelf sluit. Attributen worden overgeslagen met respect voor
// aanhalingstekens: een '>' binnen een waarde sluit de tag niet.
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

// tagNaam leest de naam van een sluit-tag en geeft de index ná de '>'.
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

// tagNaamOpen leest een elementnaam en geeft de lokale naam terug: alles ná de
// laatste ':' (een namespace-prefix zegt niets over wélk veld dit is, en S3's
// documenten hebben er één op de wortel).
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

// unescape vervangt de vijf voorgedefinieerde entiteiten en numerieke
// referenties. Een entiteit die we niet kennen is een fout: een key waarin
// "&foo;" blijft staan is geen key, en een stille doorgifte zou pas opvallen
// als iemand het object niet kan vinden.
func unescape(b []byte) (string, error) {
	if indexByteFrom(b, 0, '&') < 0 {
		return string(b), nil // het gewone geval: geen entiteit, geen werk
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != '&' {
			out = append(out, b[i])
			i++
			continue
		}
		e := indexByteFrom(b, i, ';')
		if e < 0 || e-i > 12 { // "&#x10FFFF;" is de langste die wij kennen
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

// heeft zegt of b op i met s begint.
func heeft(b []byte, i int, s string) bool {
	return len(b)-i >= len(s) && string(b[i:i+len(s)]) == s
}

// index geeft de index van s in b vanaf i, of -1. Eigen versie omdat
// strings.Index een string wil en dat hier een kopie van het antwoord zou zijn.
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
