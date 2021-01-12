package did

import (
	"encoding/json"
	"testing"

	ockamDid "github.com/ockam-network/did"
)

func TestDID_UnmarshalJSON(t *testing.T) {
	jsonTestSting := `"did:nuts:123"`

	did := DID{}
	err := json.Unmarshal([]byte(jsonTestSting), &did)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	if did.Method != "nuts" {
		t.Errorf("expected nuts got %s", did.Method)
		return
	}
}

func TestDID_MarshalJSON(t *testing.T) {
	wrappedDid, err := ockamDid.Parse("did:nuts:123")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	did := DID{*wrappedDid}
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	result, err := json.Marshal(did)
	if string(result) != `"did:nuts:123"` {
		t.Errorf("expected \"did:nuts:123\" got: %s", result)
	}
}

func TestParseDID(t *testing.T) {
	did, err := ParseDID("did:nuts:123")

	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}

	if did.String() != "did:nuts:123" {
		t.Errorf("expected parsed did to be 'did:nuts:123', got: %s", did.String())
	}
}