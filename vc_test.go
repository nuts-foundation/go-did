package did

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifiableCredential_UnmarshalCredentialSubject(t *testing.T) {
	type exampleSubject struct {
		Name string
	}
	t.Run("ok", func(t *testing.T) {
		input := VerifiableCredential{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiableCredential", "custom"],
		  "credentialSubject": {"name": "test"}
		}`), &input)
		var target []exampleSubject

		err := input.UnmarshalCredentialSubject(&target)

		assert.NoError(t, err)
		assert.Equal(t, "test", target[0].Name)
	})
}

func TestVerifiableCredential_UnmarshalProof(t *testing.T) {
	type jsonWebSignature struct {
		Jws string
	}
	t.Run("ok - single proof", func(t *testing.T) {
		input := VerifiableCredential{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiableCredential", "custom"],
		  "proof": {"jws": "test"}
		}`), &input)
		var target []jsonWebSignature

		err := input.UnmarshalProofValue(&target)

		assert.NoError(t, err)
		assert.Equal(t, "test", target[0].Jws)
	})

	t.Run("ok - multiple proof", func(t *testing.T) {
		input := VerifiableCredential{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiableCredential", "custom"],
		  "proof": [{"jws": "test"}, {"not-jws": "test"}]
		}`), &input)
		var target []jsonWebSignature

		err := input.UnmarshalProofValue(&target)

		assert.NoError(t, err)
		assert.Len(t, target, 2)
		assert.Equal(t, "test", target[0].Jws)
		assert.Equal(t, "", target[1].Jws)
	})
}

func TestVerifiableCredential_Proofs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		input := VerifiableCredential{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiableCredential", "custom"],
		  "proof": [{"type": "Ed25519Signature2018"}, {"type": "other"}]
		}`), &input)

		proofs, err := input.Proofs()

		assert.NoError(t, err)
		assert.Len(t, proofs, 2)
		assert.Equal(t, "Ed25519Signature2018", proofs[0].Type)
	})
}
