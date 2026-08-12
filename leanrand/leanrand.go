// Package leanrand geeft de vier dingen waar willekeur in een node voor
// gebruikt wordt: bytes, een id, een getal onder een grens, en jitter op een
// wachttijd. Alles uit crypto/rand, dus één bron en geen keuze te maken.
//
// Het bestaat omdat de alternatieven allemaal iets meebrengen wat je niet
// vroeg. github.com/google/uuid kostte de HopOS-kern 3.793 bytes symbolen én
// sleept database/sql/driver mee (het implementeert sql.Scanner) — voor twee
// aanroepen van de vorm uuid.New().String(), waarvan één afgekapt op acht
// tekens. Gemeten 12-08-2026 op cmd/hopos, arm64. math/rand/v2 kost niets maar
// zegt "niet voor sleutels", en dan staan er twee bronnen in één binary met
// per aanroep de vraag welke. Dus: crypto/rand, en de drie plekken waar
// handwerk fout gaat één keer goed opgeschreven.
//
// De drie plekken:
//
//   - De fout die niet kan. crypto/rand.Read vult p altijd volledig en geeft
//     nooit een fout terug (Go's eigen documentatie). Elke aanroeper schrijft
//     er tóch een tak voor, en die tak is per definitie ongetest. Hier is er
//     geen: faalt de bron, dan is dat een panic, want een node die zijn eigen
//     entropie kwijt is heeft geen zinnig vervolg.
//   - De bias van %. rand % n is scheef zodra n geen deler van 2⁶⁴ is; bij
//     kleine n onmeetbaar, bij grote n een systematische voorkeur. [N] doet
//     rejection sampling.
//   - Jitter die niemand toevoegt. Een backoff van precies 1, 2, 4, 8 seconden
//     laat honderd nodes precies gelijk opnieuw proberen. [Jitter] is één
//     aanroep om er een wolk van te maken.
//
// Wat het niet doet: geen eigen generator, geen seed, geen reproduceerbare
// stroom voor testen (die hoort in de test, niet in de bron), en geen UUID —
// een id hoeft alleen uniek te zijn, niet een formaat te volgen dat 36 tekens
// kost om 16 bytes te schrijven.
package leanrand

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// alfabet is Crockford's base32 zonder I, L, O en U: 32 tekens, dus 5 bits per
// teken zonder bias, en geen paar dat je verkeerd voorleest aan de telefoon of
// verkeerd overtypt uit een log.
const alfabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Read vult p met willekeurige bytes. Er is geen foutwaarde: crypto/rand vult
// altijd volledig, en als de bron van het systeem stuk is, is dat een panic en
// niet een halfgevulde buffer waar een sleutel uit gemaakt wordt.
func Read(p []byte) {
	if _, err := rand.Read(p); err != nil {
		panic("leanrand: the system random source failed: " + err.Error())
	}
}

// Bytes geeft n willekeurige bytes. n <= 0 geeft een lege slice.
func Bytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	Read(b)
	return b
}

// Uint64 geeft een willekeurige uint64 over het volledige bereik.
func Uint64() uint64 {
	var b [8]byte
	Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// N geeft een willekeurig getal in [0, n) — zonder bias, ook voor een n die
// geen macht van twee is. n == 0 geeft 0 (een leeg bereik heeft geen andere
// zinnige uitkomst; dat is bewust géén panic, want een grens die uit een
// lengte komt mag nul zijn).
//
// De methode is rejection sampling: alles boven de laatste hele veelvoud van n
// wordt weggegooid. De verwachte kosten zijn onder de twee trekkingen, ook in
// het slechtste geval (n net boven 2⁶³).
func N(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	// Grens = het grootste veelvoud van n dat in uint64 past. Trek opnieuw
	// zolang de waarde erboven ligt; die staart is de scheve kant.
	grens := ^uint64(0) - (^uint64(0)%n+1)%n
	for {
		v := Uint64()
		if v <= grens {
			return v % n
		}
	}
}

// Hex geeft 2n hex-tekens uit n willekeurige bytes (kleine letters, zoals de
// rest van Go's encoding/hex).
func Hex(n int) string {
	const digits = "0123456789abcdef"
	b := Bytes(n)
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// ID geeft een id van n tekens uit [alfabet]: 5 bits per teken, dus n=12 is 60
// bits en n=16 is 80. Voor een naam die in een log en een URL moet passen is
// dat ruim: bij 12 tekens zit je op één kans op een miljard na ruim veertig
// miljoen id's.
//
// n <= 0 geeft "" — een id die je niet vroeg is geen fout, maar hij is ook
// niet uniek, dus wie hem gebruikt merkt het meteen.
func ID(n int) string {
	if n <= 0 {
		return ""
	}
	b := Bytes(n)
	for i, c := range b {
		b[i] = alfabet[c&31] // 32 deelt 256: geen bias
	}
	return string(b)
}

// Jitter spreidt d met ±50%: het resultaat ligt in [d/2, 3d/2). Voor een
// backoff of een periodieke taak is dat het verschil tussen honderd nodes die
// tegelijk opnieuw proberen en honderd nodes die dat verspreid doen.
//
// d <= 0 komt onveranderd terug: geen wachttijd blijft geen wachttijd.
func Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(N(uint64(d)))
}
