package vc

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
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
		  "proof": [{"type": "JsonWebSignature2020"}, {"type": "other"}]
		}`), &input)

		proofs, err := input.Proofs()

		assert.NoError(t, err)
		assert.Len(t, proofs, 2)
		assert.Equal(t, ssi.JsonWebSignature2020, proofs[0].Type)
	})
}

func TestVerifiableCredential_IsType(t *testing.T) {
	input := VerifiableCredential{}
	json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":"VerifiableCredential"
		}`), &input)

	t.Run("true", func(t *testing.T) {
		assert.True(t, input.IsType(VerifiableCredentialTypeV1URI()))
	})

	t.Run("false", func(t *testing.T) {
		u, _ := ssi.ParseURI("type")
		assert.False(t, input.IsType(*u))
	})
}

func TestVerifiableCredential_ContainsContext(t *testing.T) {
	input := VerifiableCredential{}
	json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "@context":["https://www.w3.org/2018/credentials/v1"]
		}`), &input)

	t.Run("true", func(t *testing.T) {
		assert.True(t, input.ContainsContext(VCContextV1URI()))
	})

	t.Run("false", func(t *testing.T) {
		u, _ := ssi.ParseURI("context")
		assert.False(t, input.ContainsContext(*u))
	})
}

func TestVerifiableCredential_SubjectDID(t *testing.T) {
	t.Run("1 subject", func(t *testing.T) {
		input := VerifiableCredential{}
		input.CredentialSubject = []interface{}{map[string]interface{}{"id": "did:example:123"}}

		id, err := input.SubjectDID()

		assert.NoError(t, err)
		assert.Equal(t, "did:example:123", id.String())
	})
	t.Run("no subjects", func(t *testing.T) {
		input := VerifiableCredential{}
		input.CredentialSubject = []interface{}{}

		_, err := input.SubjectDID()

		assert.EqualError(t, err, "unable to get subject DID from VC: there must be at least 1 credentialSubject")
	})
	t.Run("1 subject without ID (not supported)", func(t *testing.T) {
		input := VerifiableCredential{}
		input.CredentialSubject = []interface{}{
			map[string]interface{}{},
		}

		_, err := input.SubjectDID()

		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have no ID")
	})
	t.Run("2 subjects with the same IDs", func(t *testing.T) {
		input := VerifiableCredential{}
		input.CredentialSubject = []interface{}{
			map[string]interface{}{"id": "did:example:123"},
			map[string]interface{}{"id": "did:example:123"},
		}

		id, err := input.SubjectDID()

		assert.NoError(t, err)
		assert.Equal(t, "did:example:123", id.String())
	})
	t.Run("2 subjects with different IDs (not supported)", func(t *testing.T) {
		input := VerifiableCredential{}
		input.CredentialSubject = []interface{}{
			map[string]interface{}{"id": "did:example:123"},
			map[string]interface{}{"id": "did:example:456"},
		}

		_, err := input.SubjectDID()

		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have the same ID")
	})
	t.Run("2 subjects, second doesn't have an IDs (not supported)", func(t *testing.T) {
		input := VerifiableCredential{}
		input.CredentialSubject = []interface{}{
			map[string]interface{}{"id": "did:example:123"},
			map[string]interface{}{},
		}

		_, err := input.SubjectDID()

		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have the same ID")
	})
	t.Run("invalid DID", func(t *testing.T) {
		input := VerifiableCredential{}
		input.CredentialSubject = []interface{}{
			map[string]interface{}{"id": "not a DID"},
		}

		_, err := input.SubjectDID()

		assert.EqualError(t, err, "unable to get subject DID from VC: invalid DID")
	})
}
