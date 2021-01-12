package did

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestController_UnmarshalJSON(t *testing.T) {

}

func Test_singleOrArray_MarshalJSON(t *testing.T) {
}

const testDocument1 = `{
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

func Test_Document(t *testing.T) {
	t.Run("it can marshal a json did into a Document", func(t *testing.T) {
		jsonDoc := `
{
	"@context": ["https://www.w3.org/ns/did/v1"],
	"id": "did:web:identity.foundation",
	"Controller": ["did:nuts:123", "did:web:example.org"]
}`
		doc := Document{}
		err := json.Unmarshal([]byte(jsonDoc), &doc)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
			return
		}
		if doc.Controller[0].String() != "did:nuts:123" {
			t.Errorf("expected 'did:nuts:123', got: %s", doc.Controller[0].String())
		}
	})

	var actual Document
	if err := json.Unmarshal([]byte(testDocument1), &actual); err != nil {
		t.Error(err)
		return
	}
	t.Run("validate ID", func(t *testing.T) {
		expected := "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff"
		if expected != actual.ID.String() {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.ID.String())
		}
	})
	t.Run("validate context", func(t *testing.T) {
		if len(actual.Context) != 1 {
			t.Errorf("expected context to contain 1 entry got: %d", len(actual.Context))
			return
		}
		expected := "https://www.w3.org/ns/did/v1"
		if expected != actual.Context[0].String() {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.Context[0].String())
		}
	})
	t.Run("validate controllers", func(t *testing.T) {
		if len(actual.Controller) != 2 {
			t.Errorf("expected controller to contain 2 entries got: %d", len(actual.Controller))
			return
		}
		expected := "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff"
		if expected != actual.Controller[0].String() {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.Controller[0].String())
		}
		expected = "did:nuts:f03a00f1-9615-4060-bd00-bd282e150c46"
		if expected != actual.Controller[1].String() {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.Controller[1].String())
		}
	})
	t.Run("it can parse assertionMethods", func(t *testing.T) {
		if !assert.Len(t, actual.AssertionMethod, 1) {
			return
		}
		assert.Equal(t, "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-1", actual.AssertionMethod[0].ID.String())
		assert.Equal(t, "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74", actual.AssertionMethod[0].PublicKeyJwk["x"])
	})
	t.Run("it can parse authentication", func(t *testing.T) {
		if !assert.Len(t, actual.Authentication, 2) {
			return
		}
		assert.Equal(t, "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-1", actual.Authentication[0].ID.String())
		assert.Equal(t, "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74", actual.Authentication[0].PublicKeyJwk["x"])
	})
	t.Run("it can parse services", func(t *testing.T) {
		if len(actual.Service) != 2 {
			t.Errorf("expected service to contain 2 entries, got: %d", len(actual.Service))
		}

		expected := "nuts:bolt:eoverdracht"
		if expected != actual.Service[0].Type {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.Service[0].Type)
		}

		expected = "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#service-1"
		if expected != actual.Service[0].ID.String() {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.Service[0].ID.String())
		}

	})

	t.Run("it can link verification relationships bases on a key id", func(t *testing.T) {
		assert.Equal(t, actual.VerificationMethod[0], *actual.AssertionMethod[0].VerificationMethod)
	})
}

func TestNormalizeDocument(t *testing.T) {
	jsonDoc := `
{
	"@context": "https://www.w3.org/ns/did/v1",
	"id": "did:web:identity.foundation",
	"controller": ["did:nuts:123", "did:web:example.org"]
}`
	expectedResult := `{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:web:identity.foundation","controller":["did:nuts:123","did:web:example.org"]}`
	normalizedDoc, err := normalizeDocument([]byte(jsonDoc))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if string(normalizedDoc) != expectedResult {
		t.Errorf("expected:\n%s\n, got:\n%s", expectedResult, normalizedDoc)
	}
}

func TestVerificationRelationship_UnmarshalJSON(t *testing.T) {
	t.Run("ok - unmarshal single did", func(t *testing.T) {
		jsonVerificationRelationship := `"did:nuts:123#key-1"`
		vRelation := VerificationRelationship{}
		err := json.Unmarshal([]byte(jsonVerificationRelationship), &vRelation)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
			return
		}
		if vRelation.reference.String() != "did:nuts:123#key-1" {
			t.Errorf("expected: \n%s\ngot:\n%s", "did:nuts:123#key-1", vRelation.ID.String())
		}
	})

	t.Run("ok - unmarshal object", func(t *testing.T) {
		jsonVerificationMethod := ` 
   {
  "id": "did:nuts:123#key-1"
}`
		vMethod := VerificationRelationship{}
		err := json.Unmarshal([]byte(jsonVerificationMethod), &vMethod)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
			return
		}
		if vMethod.ID.String() != "did:nuts:123#key-1" {
			t.Errorf("expected: \n%s\ngot:\n%s", "did:nuts:123#key-1", vMethod.ID.String())

		}
	})

	t.Run("nok - it could not pass an array", func(t *testing.T) {
		jsonVerificationMethod := `[ "did:nuts:123#key-1" ]`
		vMethod := VerificationRelationship{}
		err := json.Unmarshal([]byte(jsonVerificationMethod), &vMethod)
		if err == nil || err.Error() != "verificationRelation should be either VerificationMethod or DID" {
			t.Error("expected an error")
		}
	})
}

func TestServiceEndpoint_UnmarshalJSON(t *testing.T) {
	serviceJson := `[
	{
	  "id":"did:example:123#linked-domain",
	  "type":"custom",
	  "serviceEndpoint":"https://bar.example.com"
	},
	{
	  "id":"did:example:123#openid-connect",
	  "type":"custom",
	  "serviceEndpoint":["https://foo.example.com","https://bar.example.com"]
	}
]`
	type serviceArr []Service
	actual := serviceArr{}
	err := json.Unmarshal([]byte(serviceJson), &actual)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(actual) != 2 {
		t.Errorf("expected to see 2 services")
		return
	}

	// TODO: ServiceEndpoints
	//expected := "https://bar.example.com"
	//got := actual[0].ServiceEndpoint[expected]
	//if got == expected {
	//	t.Errorf("expected %s, got: %s", expected, got)
	//}

}
