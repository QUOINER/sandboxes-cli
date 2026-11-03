package agent

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestRegistry(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range r.Names() {
		spec, ok := r.Lookup(name)
		if !ok || !strings.HasPrefix(spec.Image, "ghcr.io/") {
			continue
		}
		if !strings.HasPrefix(spec.Image, "ghcr.io/quoiner/") {
			t.Errorf("agent %q uses a non-QUOINER GHCR image: %q", name, spec.Image)
		}
		_, digest, pinned := strings.Cut(spec.Image, "@sha256:")
		decoded, decodeErr := hex.DecodeString(digest)
		if !pinned || decodeErr != nil || len(decoded) != 32 {
			t.Errorf("agent %q GHCR image is not pinned by a SHA-256 digest: %q", name, spec.Image)
		}
	}
	kimi, ok := r.Lookup("kimi")
	if !ok || !kimi.Launchable() || !strings.HasPrefix(kimi.Image, "ghcr.io/quoiner/sandbox-kimi@sha256:") || kimi.Command[0] != "kimi" {
		t.Fatalf("kimi=%+v ok=%v", kimi, ok)
	}
	if cline, ok := r.Lookup("cline"); !ok || cline.Launchable() {
		t.Fatalf("cline=%+v ok=%v", cline, ok)
	}
	if _, ok := r.Lookup("missing"); ok {
		t.Fatal("missing agent found")
	}
	if len(r.Names()) < 10 {
		t.Fatalf("names=%v", r.Names())
	}
}
