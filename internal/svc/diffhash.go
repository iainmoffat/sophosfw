package svc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// DiffHash returns a stable hex-encoded SHA-256 over the canonical JSON
// serialization of the given typed record. Used by host_ip_update / delete
// (and future mutation paths) to detect concurrent firewall drift between
// the agent's read and the agent's write.
//
// Stability: keys are sorted alphabetically; values are encoded with
// json.Marshal (Go's default). Adding a new field to a typed record
// changes the hash for all existing records — that's intentional;
// callers re-fetch and recompute when the schema evolves.
func DiffHash(record any) (string, error) {
	canonical, err := canonicalize(record)
	if err != nil {
		return "", fmt.Errorf("diffhash: canonicalize: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalize(record any) ([]byte, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	// _diffHash is a sophosfw-injected field (Phase 12 generic object_get).
	// Strip it before hashing so the hash represents only the body shape
	// and re-hashing an already-hashed record yields the same value.
	delete(m, "_diffHash")
	return marshalSorted(m)
}

func marshalSorted(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		kb, _ := json.Marshal(k)
		out = append(out, kb...)
		out = append(out, ':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		out = append(out, vb...)
	}
	out = append(out, '}')
	return out, nil
}
