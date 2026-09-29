// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"sync"
	"time"
)

// Replay remembers which assertions have been used.
//
// saml-profiles 4.1.4.5: the SP "MUST ensure that bearer assertions are not
// replayed, by maintaining the set of used ID values for the length of time
// for which the assertion would be considered valid". A bearer assertion is
// exactly that -- whoever holds it is the person -- and a browser's history,
// a proxy's log or a shoulder is enough to hold one.
type Replay interface {
	// Use records id until expires, and says whether it was new. It must be
	// atomic: two requests with the same assertion at the same moment get
	// one true and one false.
	Use(id string, expires time.Time) bool
}

// MemoryReplay is a Replay for one process.
type MemoryReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryReplay returns an empty MemoryReplay.
func NewMemoryReplay() *MemoryReplay {
	return &MemoryReplay{seen: map[string]time.Time{}, now: time.Now}
}

// Use implements Replay. Expired entries are dropped as it goes, so the set
// is bounded by how many assertions arrive in one validity window.
func (m *MemoryReplay) Use(id string, expires time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, e := range m.seen {
		if !now.Before(e) {
			delete(m.seen, k)
		}
	}
	if _, ok := m.seen[id]; ok {
		return false
	}
	m.seen[id] = expires
	return true
}
