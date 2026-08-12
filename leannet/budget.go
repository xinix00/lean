package leannet

// budget.go — de ene knop van leannet. Alle verbindingsbuffers komen uit één
// pot van Config.Budget bytes: reserveren bij groei, terugstorten bij close.
// Niets wordt vooraf geclaimd, dus een idle listener kost niets en het
// geheugen schaalt met gebruik in plaats van met configuratie (het gemeten
// probleem van 2026-08-11, zie doc.go).

import "sync"

// budget administreert de pot. De mutex dekt alleen de telling; de bytes zelf
// alloceert de vrager (Go's allocator is de arena, wij zijn de boekhouder).
type budget struct {
	mu    sync.Mutex
	total int
	used  int
}

// reserve probeert n bytes uit de pot te claimen. false = past niet — de
// aanroeper kiest dan zelf tussen kleiner vragen of luid weigeren; stil
// wachten op geheugen doen we nooit.
func (b *budget) reserve(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || b.used+n > b.total {
		return false
	}
	b.used += n
	return true
}

// release stort n bytes terug. Meer terugstorten dan geclaimd is een
// boekhoudfout van de aanroeper en panict: stil krimpend gebruik zou élke
// budget-garantie waardeloos maken.
func (b *budget) release(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.used {
		panic("leannet: budget release exceeds reserved")
	}
	b.used -= n
}

// free geeft de vrije ruimte — een momentopname, alleen voor tuning-besluiten
// en telemetrie (de enige harde waarheid is wat reserve teruggeeft).
func (b *budget) free() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total - b.used
}
