package vc

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// jwtPresentation is taken from https://www.w3.org/TR/vc-data-model/#example-verifiable-presentation-using-jwt-compact-serialization-non-normative
const jwtPresentation = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOjB4YWJjI2tleTEifQ.e
yJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJqdGkiOiJ1cm46d
XVpZDozOTc4MzQ0Zi04NTk2LTRjM2EtYTk3OC04ZmNhYmEzOTAzYzUiLCJhdWQiOiJkaWQ6ZXhhbXBsZ
To0YTU3NTQ2OTczNDM2ZjZmNmM0YTRhNTc1NzMiLCJuYmYiOjE1NDE0OTM3MjQsImlhdCI6MTU0MTQ5M
zcyNCwiZXhwIjoxNTczMDI5NzIzLCJub25jZSI6IjM0M3MkRlNGRGEtIiwidnAiOnsiQGNvbnRleHQiO
lsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vc
mcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50Y
XRpb24iLCJDcmVkZW50aWFsTWFuYWdlclByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhb
CI6WyJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SWtwWFZDSXNJbXRwWkNJNkltUnBaRHBsZUdGd
GNHeGxPbUZpWm1VeE0yWTNNVEl4TWpBME16RmpNamMyWlRFeVpXTmhZaU5yWlhsekxURWlmUS5leUp6Z
FdJaU9pSmthV1E2WlhoaGJYQnNaVHBsWW1abFlqRm1OekV5WldKak5tWXhZekkzTm1VeE1tVmpNakVpT
ENKcWRHa2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNWxaSFV2WTNKbFpHVnVkR2xoYkhNdk16Y3pNaUlzS
W1semN5STZJbWgwZEhCek9pOHZaWGhoYlhCc1pTNWpiMjB2YTJWNWN5OW1iMjh1YW5kcklpd2libUptS
WpveE5UUXhORGt6TnpJMExDSnBZWFFpT2pFMU5ERTBPVE0zTWpRc0ltVjRjQ0k2TVRVM016QXlPVGN5T
Xl3aWJtOXVZMlVpT2lJMk5qQWhOak0wTlVaVFpYSWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZ
EhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T
2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzS
W5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSlZibWwyWlhKemFYUjVSR1ZuY
21WbFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKa1pXZHlaV1VpT
25zaWRIbHdaU0k2SWtKaFkyaGxiRzl5UkdWbmNtVmxJaXdpYm1GdFpTSTZJanh6Y0dGdUlHeGhibWM5S
jJaeUxVTkJKejVDWVdOallXeGhkWExEcVdGMElHVnVJRzExYzJseGRXVnpJRzUxYmNPcGNtbHhkV1Z6U
EM5emNHRnVQaUo5ZlgxOS5LTEpvNUdBeUJORDNMRFRuOUg3RlFva0VzVUVpOGpLd1hoR3ZvTjNKdFJhN
TF4ck5EZ1hEYjBjcTFVVFlCLXJLNEZ0OVlWbVIxTklfWk9GOG9HY183d0FwOFBIYkYySGFXb2RRSW9PQ
nh4VC00V05xQXhmdDdFVDZsa0gtNFM2VXgzclNHQW1jek1vaEVFZjhlQ2VOLWpDOFdla2RQbDZ6S1pRa
jBZUEIxcng2WDAteGxGQnM3Y2w2V3Q4cmZCUF90WjlZZ1ZXclFtVVd5cFNpb2MwTVV5aXBobXlFYkxaY
WdUeVBsVXlmbEdsRWRxclpBdjZlU2U2UnR4Snk2TTEtbEQ3YTVIVHphbllUV0JQQVVIRFpHeUdLWGRKd
y1XX3gwSVdDaEJ6STh0M2twRzI1M2ZnNlYzdFBnSGVLWEU5NGZ6X1FwWWZnLS03a0xzeUJBZlFHYmciX
X19.ft_Eq4IniBrr7gtzRfrYj8Vy1aPXuFZU-6_ai0wvaKcsrzI4JkQEKTvbJwdvIeuGuTqy7ipO-EYi
7V4TvonPuTRdpB7ZHOlYlbZ4wA9WJ6mSVSqDACvYRiFvrOFmie8rgm6GacWatgO4m4NqiFKFko3r58Lu
eFfGw47NK9RcfOkVQeHCq4btaDqksDKeoTrNysF4YS89INa-prWomrLRAhnwLOo1Etp3E4ESAxg73CR2
kA5AoMbf5KtFueWnMcSbQkMRdWcGC1VssC0tB0JffVjq7ZV6OTyV4kl1-UVgiPLXUTpupFfLRhf9QpqM
BjYgP62KvhIvW8BbkGUelYMetA`

func TestVerifiablePresentation_MarshalJSON(t *testing.T) {
	t.Run("JSON-LD", func(t *testing.T) {
		t.Run("ok - single credential and proof", func(t *testing.T) {
			input := VerifiablePresentation{
				VerifiableCredential: []VerifiableCredential{
					{
						Type: []ssi.URI{VerifiableCredentialTypeV1URI()},
					},
				},
				Proof: []interface{}{
					JSONWebSignature2020Proof{
						Jws: "",
					},
				},
			}

			bytes, err := json.Marshal(input)

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, string(bytes), "\"proof\":{")
			assert.Contains(t, string(bytes), "\"verifiableCredential\":{")
		})
	})

}

func TestVerifiablePresentation_UnmarshalProof(t *testing.T) {
	type jsonWebSignature struct {
		Jws string
	}
	t.Run("ok - single proof", func(t *testing.T) {
		input := VerifiablePresentation{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiablePresentation", "custom"],
		  "proof": {"jws": "test"}
		}`), &input)
		var target []jsonWebSignature

		err := input.UnmarshalProofValue(&target)

		assert.NoError(t, err)
		assert.Equal(t, "test", target[0].Jws)
	})

	t.Run("ok - multiple proof", func(t *testing.T) {
		input := VerifiablePresentation{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiablePresentation", "custom"],
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

func TestVerifiablePresentation_Proofs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		input := VerifiablePresentation{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#vc-1",
		  "type":["VerifiablePresentation", "custom"],
		  "proof": [{"type": "JsonWebSignature2020"}, {"type": "other"}]
		}`), &input)

		proofs, err := input.Proofs()

		assert.NoError(t, err)
		assert.Len(t, proofs, 2)
		assert.Equal(t, ssi.JsonWebSignature2020, proofs[0].Type)
	})
}

func TestVerifiablePresentation_IsType(t *testing.T) {
	input := VerifiablePresentation{}
	json.Unmarshal([]byte(`{
		  "id":"did:example:123#vp-1",
		  "type":"VerifiablePresentation"
		}`), &input)

	t.Run("true", func(t *testing.T) {
		assert.True(t, input.IsType(VerifiablePresentationTypeV1URI()))
	})

	t.Run("false", func(t *testing.T) {
		u, _ := ssi.ParseURI("type")
		assert.False(t, input.IsType(*u))
	})
}

func TestVerifiablePresentation_ContainsContext(t *testing.T) {
	input := VerifiablePresentation{}
	json.Unmarshal([]byte(`{
		  "id":"did:example:123#vp-1",
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

func TestParseVerifiablePresentation(t *testing.T) {
	t.Run("JSON-LD", func(t *testing.T) {
		raw := `{
		  "id":"did:example:123#vp-1",
		  "@context":["https://www.w3.org/2018/credentials/v1"]
		}`
		vp, err := ParseVerifiablePresentation(raw)
		require.NoError(t, err)
		require.NotNil(t, vp)
		assert.Equal(t, JSONLDPresentationProofFormat, vp.Format())
		assert.Equal(t, "did:example:123#vp-1", vp.ID.String())
		assert.Equal(t, []ssi.URI{VCContextV1URI()}, vp.Context)
		assert.Nil(t, vp.JWT())
		assert.Equal(t, raw, vp.Raw())
	})
	t.Run("JWT", func(t *testing.T) {
		vp, err := ParseVerifiablePresentation(jwtPresentation)
		require.NoError(t, err)
		require.NotNil(t, vp)
		assert.Equal(t, JWTPresentationProofFormat, vp.Format())
		assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vp.Holder.String())
		assert.Equal(t, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5", vp.ID.String())
		assert.Equal(t, []string{"did:example:4a57546973436f6f6c4a4a57573"}, vp.JWT().Audience())
		assert.Len(t, vp.Type, 2)
		assert.True(t, vp.IsType(ssi.MustParseURI("VerifiablePresentation")))
		assert.True(t, vp.IsType(ssi.MustParseURI("CredentialManagerPresentation")))
		assert.NotNil(t, vp.JWT())
		assert.Equal(t, jwtPresentation, vp.Raw())
		// Assert contained JWT VerifiableCredential was unmarshalled
		assert.Len(t, vp.VerifiableCredential, 1)
		vc := vp.VerifiableCredential[0]
		assert.Equal(t, JWTCredentialProofFormat, vc.Format())
		assert.Equal(t, "http://example.edu/credentials/3732", vc.ID.String())
	})
	t.Run("json.UnmarshalJSON for JWT-VP wrapped inside other document", func(t *testing.T) {
		type Wrapper struct {
			VP VerifiablePresentation `json:"vp"`
		}
		input := `{"vp":"` + strings.ReplaceAll(jwtPresentation, "\n", "") + `"}`
		var expected Wrapper
		err := json.Unmarshal([]byte(input), &expected)
		require.NoError(t, err)
		assert.Equal(t, JWTPresentationProofFormat, expected.VP.Format())
	})
}
