package vc

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/require"
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

func TestCredentialStatus(t *testing.T) {
	t.Run("can unmarshal JWT VC Presentation Profile JWT-VC example", func(t *testing.T) {
		// CredentialStatus example taken from https://identity.foundation/jwt-vc-presentation-profile/#vc-jwt
		// Regression: earlier defined credentialStatus.id as url.URL, which breaks since it's specified as URI by the core specification.
		expectedJSON := `{
      "id": "urn:uuid:7facf41c-1dc5-486b-87e6-587d015e76d7?bit-index=10",
      "type": "RevocationList2021Status",
      "statusListIndex": "10",
      "statusListCredential": "did:ion:EiD7M8RYnUuir2bm21uu-5YmWcqqQEie-T-jYEOEBeEWJQ:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6InNnamhTdVFsZkdYVjg1QlVSWkg5aEtQR2RhTDRlYmdSN0dERERFbkJteXMiLCJ5IjoiRGw4Z3dqazRPN2h5cDVqVjZjUjFCT3l0el9TSUZtN0ljWUlsLXBqd1JUVSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiRWNkc2FTZWNwMjU2azFWZXJpZmljYXRpb25LZXkyMDE5In1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBUjZWbjlHeGJiSFhEcDBoZjl6NV9ZT3gzcFJhZWd5LVFUdEp3YjNDcUdCdyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQ05hbDZYUnV5VjFkX2p2UlZEbmpFTXNqSUJLZjE2VzYxdDF2cndOZ1QtbVEiLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUJoOWRrSDBEdVZOUGcyTnJmWi0zZ1BmYzZXVl9CN3dOZ1hNZWlBekxBaDFnIn19?service=IdentityHub&queries=W3sibWV0aG9kIjoiQ29sbGVjdGlvbnNRdWVyeSIsInNjaGVtYSI6Imh0dHBzOi8vdzNpZC5vcmcvdmMtc3RhdHVzLWxpc3QtMjAyMS92MSIsIm9iamVjdElkIjoiZjljYTFmNDAtODg0NS00NWE1LTgwNWYtYzJlNWJjNDZhN2I5In1d"
    }`
		var actual CredentialStatus

		err := json.Unmarshal([]byte(expectedJSON), &actual)
		require.NoError(t, err)

		assert.Equal(t, "urn:uuid:7facf41c-1dc5-486b-87e6-587d015e76d7?bit-index=10", actual.ID.String())
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
