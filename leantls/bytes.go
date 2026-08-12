package leantls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Twee minuscule helpers voor het TLS-draadformaat, dat volledig uit
// lengte-geprefixte velden bestaat: een builder die de lengte achteraf invult en
// een reader die nooit buiten zijn buffer leest.
//
// Waarom niet golang.org/x/crypto/cryptobyte, dat precies dit doet: dat is de
// vierde regel van de lean-regels die we níet mogen breken (stdlib only), en het
// is veertig regels. Wat het ons hier extra oplevert is de belangrijkste
// eigenschap van de reader: élke lees geeft een fout in plaats van te paniekeren,
// want dit zijn bytes van een tegenpartij die wij niet schreven.

// builder bouwt een bytestroom met lengte-prefixen die achteraf ingevuld worden.
type builder struct {
	buf []byte
}

func (b *builder) u8(v byte)      { b.buf = append(b.buf, v) }
func (b *builder) u16(v uint16)   { b.buf = binary.BigEndian.AppendUint16(b.buf, v) }
func (b *builder) bytes(p []byte) { b.buf = append(b.buf, p...) }

// u8len/u16len/u24len schrijven een blok met zijn lengte ervoor. De lengte wordt
// gereserveerd, f() vult de inhoud, en dan gaat de echte lengte op zijn plek —
// dat is de enige vorm waarin je geen enkele lengte met de hand kunt uitrekenen,
// en handmatig uitgerekende lengtes zijn in dit protocol dé bron van fouten.
func (b *builder) u8len(f func()) {
	at := len(b.buf)
	b.buf = append(b.buf, 0)
	f()
	n := len(b.buf) - at - 1
	if n > 0xff {
		panic("leantls: u8-length block overflow")
	}
	b.buf[at] = byte(n)
}

func (b *builder) u16len(f func()) {
	at := len(b.buf)
	b.buf = append(b.buf, 0, 0)
	f()
	n := len(b.buf) - at - 2
	if n > 0xffff {
		panic("leantls: u16-length block overflow")
	}
	binary.BigEndian.PutUint16(b.buf[at:], uint16(n))
}

func (b *builder) u24len(f func()) {
	at := len(b.buf)
	b.buf = append(b.buf, 0, 0, 0)
	f()
	n := len(b.buf) - at - 3
	if n > 0xffffff {
		panic("leantls: u24-length block overflow")
	}
	b.buf[at] = byte(n >> 16)
	b.buf[at+1] = byte(n >> 8)
	b.buf[at+2] = byte(n)
}

// errShort is wat élke te korte lees oplevert. Eén sentinel, zodat de
// aanroeper hem kan herkennen zonder op tekst te matchen.
var errShort = errors.New("leantls: truncated message")

// reader leest lengte-geprefixte velden en raakt nooit buiten zijn buffer.
type reader struct {
	buf []byte
}

func (r *reader) len() int    { return len(r.buf) }
func (r *reader) empty() bool { return len(r.buf) == 0 }

func (r *reader) u8() (byte, error) {
	if len(r.buf) < 1 {
		return 0, errShort
	}
	v := r.buf[0]
	r.buf = r.buf[1:]
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if len(r.buf) < 2 {
		return 0, errShort
	}
	v := binary.BigEndian.Uint16(r.buf)
	r.buf = r.buf[2:]
	return v, nil
}

func (r *reader) u24() (uint32, error) {
	if len(r.buf) < 3 {
		return 0, errShort
	}
	v := uint32(r.buf[0])<<16 | uint32(r.buf[1])<<8 | uint32(r.buf[2])
	r.buf = r.buf[3:]
	return v, nil
}

// take pakt n rauwe bytes. Het resultaat wijst IN de buffer van de reader —
// goedkoop, en veilig omdat elke aanroeper het meteen verwerkt of kopieert.
func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || len(r.buf) < n {
		return nil, errShort
	}
	v := r.buf[:n]
	r.buf = r.buf[n:]
	return v, nil
}

// vec8/vec16/vec24 lezen een lengte-geprefixt blok en geven het als eigen reader.
func (r *reader) vec8() (reader, error) {
	n, err := r.u8()
	if err != nil {
		return reader{}, err
	}
	p, err := r.take(int(n))
	return reader{buf: p}, err
}

func (r *reader) vec16() (reader, error) {
	n, err := r.u16()
	if err != nil {
		return reader{}, err
	}
	p, err := r.take(int(n))
	return reader{buf: p}, err
}

func (r *reader) vec24() (reader, error) {
	n, err := r.u24()
	if err != nil {
		return reader{}, err
	}
	p, err := r.take(int(n))
	return reader{buf: p}, err
}

// eachExtension loopt een extensieblok af en geeft per extensie het type en de
// body. Onbekende extensies overslaan is hier GEEN slordigheid maar het
// protocol: een server mag er meer sturen dan wij kennen.
func eachExtension(r reader, f func(typ uint16, body reader) error) error {
	for !r.empty() {
		typ, err := r.u16()
		if err != nil {
			return err
		}
		body, err := r.vec16()
		if err != nil {
			return fmt.Errorf("leantls: extension %d: %w", typ, err)
		}
		if err := f(typ, body); err != nil {
			return err
		}
	}
	return nil
}
