package vc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"

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

// TestVerifiableCredential_JSONMarshalling tests JSON marshalling of VerifiableCredential.
// Credentials in JSON-LD format are marshalled JSON object, while JWT credentials are marshalled as JSON string.
func TestVerifiableCredential_JSONMarshalling(t *testing.T) {
	t.Run("JSON-LD", func(t *testing.T) {
		input := VerifiableCredential{}
		raw := `{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiableCredential", "custom"],
		  "credentialSubject": {"name": "test"},
		  "credentialStatus": {"id": "example.com", "type": "Custom"}
		}`
		err := json.Unmarshal([]byte(raw), &input)
		require.NoError(t, err)
		assert.Equal(t, "did:example:123#vc-1", input.ID.String())
		assert.Equal(t, []ssi.URI{VerifiableCredentialTypeV1URI(), ssi.MustParseURI("custom")}, input.Type)
		assert.Equal(t, []interface{}{map[string]interface{}{"name": "test"}}, input.CredentialSubject)
		assert.Equal(t, []interface{}{map[string]interface{}{"id": "example.com", "type": "Custom"}}, input.CredentialStatus)
		assert.Equal(t, JSONLDCredentialProofFormat, input.Format())
		assert.Equal(t, raw, input.Raw())
		assert.Nil(t, input.JWT())
		// Should marshal into JSON object
		marshalled, err := json.Marshal(input)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(marshalled), "{"))

		t.Run("marshal empty VC", func(t *testing.T) {
			input := VerifiableCredential{}
			actual, err := json.Marshal(input)
			require.NoError(t, err)
			const expected = "{\"@context\":null,\"credentialSubject\":null,\"issuer\":\"\",\"proof\":null,\"type\":null}"
			assert.JSONEq(t, expected, string(actual))
		})
	})
	t.Run("JWT", func(t *testing.T) {
		input := VerifiableCredential{}
		raw := strings.ReplaceAll(jwtCredential, "\n", "")
		err := json.Unmarshal([]byte(`"`+raw+`"`), &input)
		require.NoError(t, err)
		assert.Equal(t, []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("UniversityDegreeCredential")}, input.Type)
		assert.Len(t, input.CredentialSubject, 1)
		assert.NotNil(t, input.CredentialSubject[0].(map[string]interface{})["degree"])
		assert.Equal(t, JWTCredentialProofFormat, input.Format())
		assert.Equal(t, raw, input.Raw())
		assert.NotNil(t, input.JWT())
		// Should marshal into JSON string
		marshalled, err := json.Marshal(input)
		require.NoError(t, err)
		assert.JSONEq(t, `"`+raw+`"`, string(marshalled))
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
	t.Run("JWT without `exp` and `nbf` claim", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, token.Set("vc", map[string]interface{}{}))
		keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, keyPair))
		require.NoError(t, err)
		credential, err := ParseVerifiableCredential(string(tokenBytes))
		require.NoError(t, err)
		assert.Equal(t, JWTCredentialProofFormat, credential.Format())
		assert.Nil(t, credential.ExpirationDate)
		assert.Empty(t, credential.IssuanceDate)
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

func TestVerifiableCredential_UnmarshalCredentialStatus(t *testing.T) {
	type CustomCredentialStatus struct {
		Id          string `json:"id,omitempty"`
		Type        string `json:"type,omitempty"`
		CustomField string `json:"customField,omitempty"`
	}
	expectedJSON := `
			{ "credentialStatus": {
				"id": "not a uri but doesn't fail",
				"type": "CustomType",
				"customField": "not empty"
			  }
			}`
	// custom status that contains more fields than CredentialStatus
	cred := VerifiableCredential{}
	require.NoError(t, json.Unmarshal([]byte(expectedJSON), &cred))
	var target []CustomCredentialStatus

	err := cred.UnmarshalCredentialStatus(&target)

	assert.NoError(t, err)
	require.Len(t, target, 1)
	assert.Equal(t, "CustomType", target[0].Type)
	assert.Equal(t, "not empty", target[0].CustomField)
}

func TestVerifiableCredential_CredentialStatuses(t *testing.T) {
	expectedJSON := `
			{ "credentialStatus": {
				"id": "valid.uri",
				"type": "CustomType",
				"customField": "not empty"
			  }
			}`
	cred := VerifiableCredential{}
	require.NoError(t, json.Unmarshal([]byte(expectedJSON), &cred))

	statuses, err := cred.CredentialStatuses()

	assert.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, ssi.MustParseURI("valid.uri"), statuses[0].ID)
	assert.Equal(t, "CustomType", statuses[0].Type)
	assert.NotEmpty(t, statuses[0].Raw())
}

func TestCredentialStatus_UnmarshalJSON(t *testing.T) {
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
		assert.Greater(t, len(actual.raw), 1)
	})
}

func TestCredentialStatus_Raw(t *testing.T) {
	orig := CredentialStatus{
		ID:   ssi.MustParseURI("something"),
		Type: "statusType",
	}
	bs, _ := json.Marshal(orig)

	var remarshalled CredentialStatus
	require.NoError(t, json.Unmarshal(bs, &remarshalled))

	raw := remarshalled.Raw()
	require.Greater(t, len(raw), 1) // make sure raw exists, and we do not end up creating a new slice

	assert.Equal(t, raw, remarshalled.raw)
	raw[0] = 'x' // was '{'
	assert.NotEqual(t, raw, remarshalled.raw)
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

func TestCreateJWTVerifiableCredential(t *testing.T) {
	issuerDID := did.MustParseDID("did:example:issuer")
	subjectDID := did.MustParseDID("did:example:subject")
	credentialID := ssi.MustParseURI(issuerDID.String() + "#1")
	issuanceDate := time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
	expirationDate := issuanceDate.AddDate(0, 0, 10)
	template := VerifiableCredential{
		ID: &credentialID,
		Context: []ssi.URI{
			VCContextV1URI(),
		},
		Type: []ssi.URI{
			VerifiableCredentialTypeV1URI(),
			ssi.MustParseURI("https://example.com/custom"),
		},
		IssuanceDate:   &issuanceDate,
		ExpirationDate: &expirationDate,
		CredentialSubject: []interface{}{
			map[string]interface{}{
				"id": subjectDID.String(),
			},
		},
		Issuer: issuerDID.URI(),
	}
	captureFn := func(claims *map[string]any, headers *map[string]any) func(_ context.Context, c map[string]interface{}, h map[string]interface{}) (string, error) {
		return func(_ context.Context, c map[string]interface{}, h map[string]interface{}) (string, error) {
			if claims != nil {
				*claims = c
			}
			if headers != nil {
				*headers = h
			}
			return jwtCredential, nil
		}
	}
	ctx := context.Background()
	t.Run("all properties", func(t *testing.T) {
		var claims map[string]interface{}
		var headers map[string]interface{}
		_, err := CreateJWTVerifiableCredential(ctx, template, captureFn(&claims, &headers))
		assert.NoError(t, err)
		assert.Equal(t, issuerDID.String(), claims[jwt.IssuerKey])
		assert.Equal(t, subjectDID.String(), claims[jwt.SubjectKey])
		assert.Equal(t, template.ID.String(), claims[jwt.JwtIDKey])
		assert.Equal(t, issuanceDate, claims[jwt.NotBeforeKey])
		assert.Equal(t, expirationDate, claims[jwt.ExpirationKey])
		assert.Equal(t, map[string]interface{}{
			"credentialSubject": template.CredentialSubject,
			"@context":          template.Context,
			"type":              template.Type,
		}, claims["vc"])
		assert.Equal(t, map[string]interface{}{"typ": "JWT"}, headers)
	})
	t.Run("only mandatory properties", func(t *testing.T) {
		minimumTemplate := VerifiableCredential{CredentialSubject: template.CredentialSubject}
		var claims map[string]interface{}
		_, err := CreateJWTVerifiableCredential(ctx, minimumTemplate, captureFn(&claims, nil))
		assert.NoError(t, err)
		assert.Nil(t, claims[jwt.NotBeforeKey])
		assert.Nil(t, claims[jwt.ExpirationKey])
		assert.Nil(t, claims[jwt.JwtIDKey])
	})
	t.Run("error - cannot use validFrom", func(t *testing.T) {
		template := VerifiableCredential{
			CredentialSubject: template.CredentialSubject,
			ValidFrom:         &issuanceDate,
		}
		_, err := CreateJWTVerifiableCredential(ctx, template, captureFn(nil, nil))
		assert.EqualError(t, err, "cannot use validFrom/validUntil to generate JWT-VCs")
	})
	t.Run("error - cannot use validUntil", func(t *testing.T) {
		template := VerifiableCredential{
			CredentialSubject: template.CredentialSubject,
			ValidUntil:        &expirationDate,
		}
		_, err := CreateJWTVerifiableCredential(ctx, template, captureFn(nil, nil))
		assert.EqualError(t, err, "cannot use validFrom/validUntil to generate JWT-VCs")
	})
}

func TestVerifiableCredential_ValidAt(t *testing.T) {
	lll := time.Date(1999, 0, 0, 0, 0, 0, 0, time.UTC)
	hhh := time.Date(2001, 0, 0, 0, 0, 0, 0, time.UTC)

	// no validity period is always true; includes missing IssuanceDate(.IsZero() == true)
	assert.True(t, VerifiableCredential{}.ValidAt(time.Now()))

	// valid on bounds
	assert.True(t, VerifiableCredential{IssuanceDate: &lll, ValidFrom: &lll}.ValidAt(lll))
	assert.True(t, VerifiableCredential{ExpirationDate: &lll, ValidUntil: &lll}.ValidAt(lll))

	// invalid
	assert.False(t, VerifiableCredential{IssuanceDate: &hhh, ValidFrom: &lll}.ValidAt(lll))
	assert.False(t, VerifiableCredential{IssuanceDate: &lll, ValidFrom: &hhh}.ValidAt(lll))
	assert.False(t, VerifiableCredential{ExpirationDate: &hhh, ValidUntil: &lll}.ValidAt(hhh))
	assert.False(t, VerifiableCredential{ExpirationDate: &lll, ValidUntil: &hhh}.ValidAt(hhh))
}
