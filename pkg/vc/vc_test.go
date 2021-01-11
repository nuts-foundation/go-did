package vc

import (
	"encoding/json"
	"github.com/nuts-foundation/golang-didparser/pkg"
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
	"time"
)

func TestUnmarshalVC(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected interface{}
	}{
		// Test case: basic OK flow
		{"ok - basic flow", `
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "did:nuts:123/credentials/1",
  "type": ["VerifiableCredential", "NutsNameCredential"],
  "issuer": "did:nuts:123",
  "issuanceDate": "2020-01-11T09:56:24Z",
  "expirationDate": "2025-01-11T09:56:24Z",
  "credentialSubject": {
    "id": "did:nuts:123",
    "name": "Verpleegtehuis de nootjes",
    "locality": "Groenlo"
  },
  "proof": {
    "type": "RsaSignature2018",
    "created": "2017-06-18T21:19:10Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:nuts:1#key-1",
    "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
  }
}`,
			VerifiableCredential{
				Context:        []pkg.URI{uri("https://www.w3.org/2018/credentials/v1")},
				Type:           []string{"VerifiableCredential", "NutsNameCredential"},
				Issuer:         uri("did:nuts:123"),
				IssuanceDate:   time.Date(2020, 01, 11, 9, 56, 24, 0, time.UTC),
				ExpirationDate: time.Date(2025, 01, 11, 9, 56, 24, 0, time.UTC),
				Subject: []StructuredData{
					{
						ID: uri("did:nuts:123"),
						Properties: map[string]interface{}{
							"name":     "Verpleegtehuis de nootjes",
							"locality": "Groenlo",
						},
					},
				},
			}},
		// Test case: empty input
		{name: "ok - empty input", input: `{}`, expected: VerifiableCredential{}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := VerifiableCredential{}
			err := json.Unmarshal([]byte(testCase.input), &actual)
			if expectedError, expectErr := testCase.expected.(error); expectErr {
				assert.EqualError(t, err, expectedError.Error())
			} else {
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, testCase.expected, actual)
			}
		})
	}
}

func TestStructuredData_UnmarshalJSON(t *testing.T) {
	t.Run("error - ID is not a string", func(t *testing.T) {
		err := json.Unmarshal([]byte(`{"id": false}`), &StructuredData{})
		assert.EqualError(t, err, "'id' isn't a string")
	})
	t.Run("error - ID is empty", func(t *testing.T) {
		err := json.Unmarshal([]byte(`{"id": ""}`), &StructuredData{})
		assert.EqualError(t, err, "'id' is empty")
	})
	t.Run("error - ID is not a valid URI", func(t *testing.T) {
		err := json.Unmarshal([]byte(`{"id": "`+string(rune(0x7f))+`"}`), &StructuredData{})
		assert.Contains(t, err.Error(), "invalid control character in URL")
	})
}

func TestStructuredData_Unmarshal(t *testing.T) {
	input := `{
		"id": "did:nuts:123",
		"name": "Verpleegtehuis de nootjes",
		"locality": "Groenlo"
	  }`
	sd := StructuredData{}
	err := json.Unmarshal([]byte(input), &sd)
	if !assert.NoError(t, err) {
		return
	}
	type specificType struct {
		Name     string
		Locality string
	}
	actual := specificType{}
	expected := specificType{
		Name:     "Verpleegtehuis de nootjes",
		Locality: "Groenlo",
	}
	err = sd.Unmarshal(&actual)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, expected, actual)
}

func uri(input string) pkg.URI {
	underlying, _ := url.Parse(input)
	return pkg.URI{URL: *underlying}
}
