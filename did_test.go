package did

import (
	"encoding/json"
	"testing"

	ockamDid "github.com/ockam-network/did"
	"github.com/stretchr/testify/assert"
)

func TestDID_UnmarshalJSON(t *testing.T) {
	jsonTestSting := `"did:nuts:123"`

	id := DID{}
	err := json.Unmarshal([]byte(jsonTestSting), &id)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	if id.Method != "nuts" {
		t.Errorf("expected nuts got %s", id.Method)
		return
	}
}

func TestDID_MarshalJSON(t *testing.T) {
	wrappedDid, err := ockamDid.Parse("did:nuts:123")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	id := DID{*wrappedDid}
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	result, err := json.Marshal(id)
	if string(result) != `"did:nuts:123"` {
		t.Errorf("expected \"did:nuts:123\" got: %s", result)
	}
}

func TestParseDID(t *testing.T) {
	id, err := ParseDID("did:nuts:123")

	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}

	if id.String() != "did:nuts:123" {
		t.Errorf("expected parsed did to be 'did:nuts:123', got: %s", id.String())
	}
}

func TestDID_Empty(t *testing.T) {
	t.Run("not empty for filled did", func(t *testing.T) {
		id, err := ParseDID("did:nuts:123")
		if err != nil {
			t.Errorf("unexpected error: %s", err)
			return
		}
		assert.False(t, id.Empty())
	})

	t.Run("empty when just generated", func(t *testing.T) {
		id := DID{}
		assert.True(t, id.Empty())
	})
}
