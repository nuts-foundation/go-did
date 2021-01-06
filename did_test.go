package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseDIDDocument(t *testing.T) {
	input := `{
  "@context": [
    "https://www.w3.org/ns/did/v1"
  ],
  "id": "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff",
  "controller": [
    "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff",
    "did:nuts:f03a00f1-9615-4060-bd00-bd282e150c46"
  ],
  "verificationMethod": [
    {
      "id": "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff",
      "publicKeyJwk": {
        "kty" : "EC",
		"crv" : "P-256",
		"x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
		"y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
  	  }
    },
    {
      "id": "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff",
      "publicKeyJwk": {
        "kty" : "EC",
		"crv" : "P-256",
		"x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
		"y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
  	  }
    }
  ],
  "authentication": [
    "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-1",
    "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-2"
  ],
  "assertionMethod": [
    "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-1"
  ],
  "service": [
    {
      "id": "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#service-1",
      "type": "nuts:bolt:eoverdracht",
      "serviceEndpoint": "did:nuts:<vendor>#service-76"
    },
    {
      "id": "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#service-2",
      "type": "nuts:core:consent",
      "serviceEndpoint": "did:nuts:<vendor>#service-2"
    }
  ]
}`

	var actual didDocument
	if err := json.Unmarshal([]byte(input), &actual); err != nil {
		t.Error(err)
		return
	}
	t.Run("validate ID", func(t *testing.T) {
		assert.Equal(t, "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff", actual.ID.String())
	})
	t.Run("validate context", func(t *testing.T) {
		assert.Len(t, actual.Context, 1)
		assert.Equal(t, "https://www.w3.org/ns/did/v1", actual.Context[0].String())
	})
	t.Run("validate controllers", func(t *testing.T) {
		assert.Len(t, actual.Controllers, 2)
		assert.Equal(t, "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff", actual.Controllers[0].String())
		assert.Equal(t, "did:nuts:f03a00f1-9615-4060-bd00-bd282e150c46", actual.Controllers[1].String())
	})

}

func TestDIDList_UnmarshalJSON(t *testing.T) {
	input := `{
	  "id": "<nuts did id>",
	  "controller": "ctrl1",
	  "verificationMethod": [],
	  "authentication": [],
	  "service":[]
	}`
	var actual didDocument
	if err := json.Unmarshal([]byte(input), &actual); err != nil {
		t.Error(err)
		return
	}

}
