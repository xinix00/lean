package leanh2

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// De voorbeelden uit RFC 7541 bijlage C: dat is de enige toets die niet
// meebeweegt met onze eigen aannames.
func TestRFC7541Examples(t *testing.T) {
	cases := []struct {
		naam  string
		hex   string
		want  []field
		limit int
	}{
		{
			// C.2.1 — literal met indexering, naam als letterreeks.
			naam: "C.2.1 literal met indexering",
			hex:  "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
			want: []field{{"custom-key", "custom-header"}},
		},
		{
			// C.2.2 — literal zonder indexering, naam uit de statische tabel.
			naam: "C.2.2 literal zonder indexering",
			hex:  "040c2f73616d706c652f70617468",
			want: []field{{":path", "/sample/path"}},
		},
		{
			// C.2.4 — geïndexeerd veld (statisch 2 = :method GET).
			naam: "C.2.4 geindexeerd",
			hex:  "82",
			want: []field{{":method", "GET"}},
		},
		{
			// C.3.1 — een echt verzoek, vier velden.
			naam: "C.3.1 verzoek zonder huffman",
			hex:  "828684410f7777772e6578616d706c652e636f6d",
			want: []field{
				{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
				{":authority", "www.example.com"},
			},
		},
		{
			// C.4.1 — hetzelfde verzoek mét Huffman-letters.
			naam: "C.4.1 verzoek met huffman",
			hex:  "828684418cf1e3c2e5f23a6ba0ab90f4ff",
			want: []field{
				{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
				{":authority", "www.example.com"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.naam, func(t *testing.T) {
			block, err := hex.DecodeString(c.hex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := newDecoder(4096, 0).decode(block)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("velden:\n got %v\nwant %v", got, c.want)
			}
		})
	}
}

// De dynamische tabel over meerdere blokken heen: C.3 stuurt drie verzoeken
// achter elkaar en het derde leunt volledig op wat de eerste twee indexeerden.
func TestDynamicTableAcrossBlocks(t *testing.T) {
	dec := newDecoder(4096, 0)
	for i, c := range []struct {
		hex  string
		want []field
	}{
		{"828684410f7777772e6578616d706c652e636f6d", []field{
			{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}},
		{"828684be58086e6f2d6361636865", []field{
			{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
			{":authority", "www.example.com"}, {"cache-control", "no-cache"}}},
		{"828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", []field{
			{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"},
			{":authority", "www.example.com"}, {"custom-key", "custom-value"}}},
	} {
		block, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := dec.decode(block)
		if err != nil {
			t.Fatalf("verzoek %d: %v", i+1, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("verzoek %d:\n got %v\nwant %v", i+1, got, c.want)
		}
	}
}

// Het echte blok dat de Cloudflare-edge stuurde toen hij zijn control-stream
// opende (spike 19-08, 87 bytes van region1.v2.argotunnel.com). Dit is de
// enige test die bewijst dat we de peer aankunnen die ons daadwerkelijk belt.
func TestCloudflareControlStreamHeaders(t *testing.T) {
	const block = "419521ea4d87a16426c28e95c941ed925a0761645c87a7828487409c24ab1283db24" +
		"b40ec2c8b5761fcfa5887aaa291263d4b5b5cd60e42f8a21ea4d87a16426c28e9f" +
		"50839bd9ab7a8dc475a74a6b589418b525812e0f"
	raw, err := hex.DecodeString(block)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newDecoder(4096, 1<<20).decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Niet op de exacte lijst toetsen: dit blok is een opname en de edge mag
	// zijn koppen veranderen. Wat vast is: dit móet de control-stream zijn.
	var upgrade, authority string
	for _, f := range got {
		switch f.name {
		case "cf-cloudflared-proxy-connection-upgrade":
			upgrade = f.value
		case ":authority":
			authority = f.value
		}
	}
	if upgrade != "control-stream" {
		t.Errorf("upgrade-kop = %q, wil control-stream (velden: %v)", upgrade, got)
	}
	if authority == "" {
		t.Errorf(":authority ontbreekt (velden: %v)", got)
	}
}

// Padding die geen prefix van EOS is, en een halve code die te lang doorloopt:
// beide horen te weigeren in plaats van stil af te ronden.
func TestHuffmanRejectsBadPadding(t *testing.T) {
	for _, c := range []struct{ naam, hex string }{
		{"padding met een nul erin", "8100"},
		{"te lange staart", "83ffffff"},
	} {
		t.Run(c.naam, func(t *testing.T) {
			raw, _ := hex.DecodeString(c.hex)
			if _, err := newDecoder(4096, 0).decode(raw); err == nil {
				t.Error("geen fout, wel een verwachte weigering")
			}
		})
	}
}

// Coderen: wat wij schrijven moet elke HPACK-decoder kunnen lezen — dus toets
// het met onze eigen decoder, die de RFC-voorbeelden al haalt.
func TestEncodeRoundTrip(t *testing.T) {
	fields := []field{
		{":status", "200"},
		{"content-type", "image/jpeg"},
		{"cf-ray", "8f3a1b2c4d5e6f70-AMS"},
		{"x-leeg", ""},
	}
	block := encodeFields(nil, fields)
	got, err := newDecoder(4096, 0).decode(block)
	if err != nil {
		t.Fatalf("Decode van onze eigen codering: %v", err)
	}
	if !reflect.DeepEqual(got, fields) {
		t.Errorf("rondgang:\n got %v\nwant %v", got, fields)
	}
	// :status 200 hoort één byte te zijn (statische index 8).
	if block[0] != 0x88 {
		t.Errorf("status 200 gecodeerd als 0x%02x, wil 0x88", block[0])
	}
}

// De grens op de kop-lijst moet dichtklappen, anders kan één frame ons geheugen
// laten groeien op een node die 32MB heeft.
func TestHeaderListLimit(t *testing.T) {
	fields := make([]field, 64)
	for i := range fields {
		fields[i] = field{"x-vulling", "0123456789012345678901234567890123456789"}
	}
	block := encodeFields(nil, fields)
	if _, err := newDecoder(4096, 1024).decode(block); err == nil {
		t.Error("geen fout boven de lijstgrens")
	}
}
