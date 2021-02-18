package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/go-did/test"
)

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
	if err := json.Unmarshal(test.ReadTestFile("test/did1.json"), &actual); err != nil {
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
	const expectedKeyID = "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#key-1"
	t.Run("it can parse assertionMethods", func(t *testing.T) {
		if !assert.Len(t, actual.AssertionMethod, 1) {
			return
		}
		assert.Equal(t, expectedKeyID, actual.AssertionMethod[expectedKeyID].ID.String())
		assert.Equal(t, "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74", actual.AssertionMethod[expectedKeyID].PublicKeyJwk["x"])
	})
	t.Run("it can parse authentication", func(t *testing.T) {
		if !assert.Len(t, actual.Authentication, 2) {
			return
		}
		assert.Equal(t, expectedKeyID, actual.Authentication[expectedKeyID].ID.String())
		assert.Equal(t, "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74", actual.Authentication[expectedKeyID].PublicKeyJwk["x"])
	})
	t.Run("it can parse services", func(t *testing.T) {
		if len(actual.Service) != 2 {
			t.Errorf("expected service to contain 2 entries, got: %d", len(actual.Service))
		}

		expected := "nuts:bolt:eoverdracht"
		const expectedID = "did:nuts:04cf1e20-378a-4e38-ab1b-401a5018c9ff#service-1"
		if expected != actual.Service[expectedID].Type {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.Service[expectedID].Type)
		}

		if expectedID != actual.Service[expectedID].ID.String() {
			t.Errorf("expected:\n%s\n, got:\n%s", expectedID, actual.Service[expectedID].ID.String())
		}

	})

	t.Run("it can link verification relationships bases on a key id", func(t *testing.T) {
		assert.Equal(t, actual.VerificationMethod[0], actual.AssertionMethod[expectedKeyID].VerificationMethod)
	})

	t.Run("it can add assertionMethods with json web key", func(t *testing.T) {
		id := actual.ID
		id.Fragment = "added-assertion-method-1"

		keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		vm, err := NewVerificationMethod(id, JsonWebKey2020, actual.ID, keyPair.PublicKey)
		if !assert.NoError(t, err) {
			return
		}

		actual.AddAssertionMethod(vm)
		//assert.NoError(t, err, "unable to add a new assertionMethod to document")
		didJson, _ := json.MarshalIndent(actual, "", "  ")
		t.Logf("resulting json:\n%s", didJson)
	})

	t.Run("it can add assertionMethods with ED25519VerificationKey2018", func(t *testing.T) {
		id := actual.ID
		id.Fragment = "added-assertion-method-1"

		pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
		vm, err := NewVerificationMethod(id, ED25519VerificationKey2018, actual.ID, pubKey)
		if !assert.NoError(t, err) {
			return
		}

		actual.AddAssertionMethod(vm)
		didJson, _ := json.MarshalIndent(actual, "", "  ")
		t.Logf("resulting json:\n%s", didJson)
	})

	t.Run("it can parse a jwk in a verification method", func(t *testing.T) {
		keyAsJWK, err := actual.Authentication[expectedKeyID].JWK()
		if !assert.NoError(t, err, "expected key to be converted to a jwk.key") {
			return
		}
		assert.Equal(t, "EC", keyAsJWK.KeyType().String())
	})
}

func TestRoundTripMarshalling(t *testing.T) {
	testCases := []string{
		"did1",
	}

	for _, testCase := range testCases {
		t.Run(testCase, func(t *testing.T) {
			document := Document{}
			err := json.Unmarshal(test.ReadTestFile("test/"+testCase+".json"), &document)
			if !assert.NoError(t, err) {
				return
			}
			marshaled, err := json.Marshal(document)
			if !assert.NoError(t, err) {
				return
			}
			println(string(marshaled))
			assert.JSONEq(t, string(test.ReadTestFile("test/"+testCase+"-expected.json")), string(marshaled))
		})
	}
}

func TestVerificationRelationship_UnmarshalJSON(t *testing.T) {
	t.Run("ok - unmarshal single did", func(t *testing.T) {
		input := `"did:nuts:123#key-1"`
		actual := VerificationRelationship{}
		err := json.Unmarshal([]byte(input), &actual)
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:123#key-1", actual.reference.String())
	})
	t.Run("ok - unmarshal object", func(t *testing.T) {
		input := `{"id": "did:nuts:123#key-1"}`
		actual := VerificationRelationship{}
		err := json.Unmarshal([]byte(input), &actual)
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:123#key-1", actual.ID.String())
	})
}

func TestService_UnmarshalJSON(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		actual := Service{}
		err := json.Unmarshal([]byte(`{
		  "id":"did:example:123#linked-domain",
		  "type":"custom",
		  "serviceEndpoint": ["foo", "bar"]
		}`), &actual)
		assert.NoError(t, err)
		assert.Equal(t, "did:example:123#linked-domain", actual.ID.String())
		assert.Equal(t, "custom", actual.Type)
		assert.IsType(t, []interface{}{}, actual.ServiceEndpoint)
	})
	t.Run("ok - empty", func(t *testing.T) {
		actual := Service{}
		err := json.Unmarshal([]byte("{}"), &actual)
		assert.NoError(t, err)
	})
}

func TestService_UnmarshalServiceEndpoint(t *testing.T) {
	type targetType struct {
		Value string
	}
	t.Run("ok", func(t *testing.T) {
		input := Service{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#linked-domain",
		  "type":"custom",
		  "serviceEndpoint": {"value": "foobar"}
		}`), &input)
		var target targetType
		err := input.UnmarshalServiceEndpoint(&target)
		assert.NoError(t, err)
		assert.Equal(t, "foobar", target.Value)
	})
}
