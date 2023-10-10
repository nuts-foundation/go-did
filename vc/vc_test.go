package vc

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// jwtCredential is taken from https://www.w3.org/TR/vc-data-model/#example-verifiable-credential-using-jwt-compact-serialization-non-normative
const jwtCredential = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmFiZmUxM2Y3MTIxMjA0
MzFjMjc2ZTEyZWNhYiNrZXlzLTEifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxY
zI3NmUxMmVjMjEiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsImlzc
yI6Imh0dHBzOi8vZXhhbXBsZS5jb20va2V5cy9mb28uandrIiwibmJmIjoxNTQxNDkzNzI0LCJpYXQiO
jE1NDE0OTM3MjQsImV4cCI6MTU3MzAyOTcyMywibm9uY2UiOiI2NjAhNjM0NUZTZXIiLCJ2YyI6eyJAY
29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd
3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZ
UNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjd
CI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IjxzcGFuIGxhbmc9J2ZyL
UNBJz5CYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzPC9zcGFuPiJ9fX19.KLJo5GAy
BND3LDTn9H7FQokEsUEi8jKwXhGvoN3JtRa51xrNDgXDb0cq1UTYB-rK4Ft9YVmR1NI_ZOF8oGc_7wAp
8PHbF2HaWodQIoOBxxT-4WNqAxft7ET6lkH-4S6Ux3rSGAmczMohEEf8eCeN-jC8WekdPl6zKZQj0YPB
1rx6X0-xlFBs7cl6Wt8rfBP_tZ9YgVWrQmUWypSioc0MUyiphmyEbLZagTyPlUyflGlEdqrZAv6eSe6R
txJy6M1-lD7a5HTzanYTWBPAUHDZGyGKXdJw-W_x0IWChBzI8t3kpG253fg6V3tPgHeKXE94fz_QpYfg
--7kLsyBAfQGbg`

func TestVerifiableCredential_UnmarshalJSON(t *testing.T) {
	t.Run("JSON-LD", func(t *testing.T) {
		input := VerifiableCredential{}
		raw := `{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiableCredential", "custom"],
		  "credentialSubject": {"name": "test"}
		}`
		err := json.Unmarshal([]byte(raw), &input)
		require.NoError(t, err)
		assert.Equal(t, "did:example:123#vc-1", input.ID.String())
		assert.Equal(t, []ssi.URI{VerifiableCredentialTypeV1URI(), ssi.MustParseURI("custom")}, input.Type)
		assert.Equal(t, []interface{}{map[string]interface{}{"name": "test"}}, input.CredentialSubject)
		assert.Equal(t, JSONLDCredentialProofFormat, input.Format())
		assert.Equal(t, raw, input.Raw())
		assert.Nil(t, input.JWT())
	})
	t.Run("JWT", func(t *testing.T) {
		input := VerifiableCredential{}
		raw := strings.ReplaceAll(jwtCredential, "\n", "")
		err := json.Unmarshal([]byte(`"`+raw+`"`), &input)
		require.NoError(t, err)
		assert.Equal(t, []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("UniversityDegreeCredential")}, input.Type)
		assert.Len(t, input.CredentialSubject, 1)
		assert.NotNil(t, input.CredentialSubject[0].(map[string]interface{})["degree"])
		assert.Equal(t, JWTCredentialsProofFormat, input.Format())
		assert.Equal(t, raw, input.Raw())
		assert.NotNil(t, input.JWT())
	})
}

func TestParseVerifiableCredential(t *testing.T) {
	t.Run("JSON-LD", func(t *testing.T) {
		input := VerifiableCredential{}
		err := json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiableCredential", "custom"],
		  "credentialSubject": {"name": "test"}
		}`), &input)
		require.NoError(t, err)
		assert.Equal(t, "did:example:123#vc-1", input.ID.String())
		assert.Equal(t, []ssi.URI{VerifiableCredentialTypeV1URI(), ssi.MustParseURI("custom")}, input.Type)
		assert.Equal(t, []interface{}{map[string]interface{}{"name": "test"}}, input.CredentialSubject)
	})
	t.Run("JWT", func(t *testing.T) {
		input := VerifiableCredential{}
		err := json.Unmarshal([]byte(`"`+strings.ReplaceAll(jwtCredential, "\n", "")+`"`), &input)
		require.NoError(t, err)
		assert.Equal(t, []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("UniversityDegreeCredential")}, input.Type)
		assert.Len(t, input.CredentialSubject, 1)
		assert.NotNil(t, input.CredentialSubject[0].(map[string]interface{})["degree"])
	})
}

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
