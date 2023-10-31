package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/go-did/did/test"
)

func Test_Document(t *testing.T) {
	id123, _ := ParseDID("did:example:123")
	id123Method, _ := ParseDIDURL("did:example:123#method")
	id456, _ := ParseDID("did:example:456")

	t.Run("it can marshal a json did into a Document", func(t *testing.T) {
		jsonDoc := `
{
	"@context": ["https://www.w3.org/ns/did/v1"],
	"id": "did:web:identity.foundation",
	"controller": ["did:nuts:123", "did:web:example.com"],
	"alsoKnownAs": ["did:web:example.com"]
}`
		doc := Document{}
		err := json.Unmarshal([]byte(jsonDoc), &doc)

		require.NoError(t, err)
		assert.Equal(t, "did:web:identity.foundation", doc.ID.String())
		assert.Equal(t, "did:nuts:123", doc.Controller[0].String())
		assert.Equal(t, "did:web:example.com", doc.Controller[1].String())
		assert.Equal(t, "did:web:example.com", doc.AlsoKnownAs[0].String())
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
		if expected != actual.Context[0].(string) {
			t.Errorf("expected:\n%s\n, got:\n%s", expected, actual.Context[0].(string))
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
		assert.Equal(t, actual.VerificationMethod[0], actual.AssertionMethod[0].VerificationMethod)
	})

	t.Run("it can add assertionMethods with json web key", func(t *testing.T) {
		id := actual.ID
		id.Fragment = "added-assertion-method-1"

		keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		vm, err := NewVerificationMethod(id, ssi.JsonWebKey2020, actual.ID, keyPair.PublicKey)
		if !assert.NoError(t, err) {
			return
		}

		actual.AddAssertionMethod(vm)
		//assert.NoError(t, err, "unable to add a new assertionMethod to document")
		didJson, _ := json.MarshalIndent(actual, "", "  ")
		t.Logf("resulting json:\n%s", didJson)
	})

	t.Run("ED25519VerificationKey2018", func(t *testing.T) {
		id := actual.ID
		id.Fragment = "1"

		pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
		vm, err := NewVerificationMethod(id, ssi.ED25519VerificationKey2018, actual.ID, pubKey)
		require.NoError(t, err)

		publicKey, err := vm.PublicKey()
		require.NoError(t, err)
		require.NotNil(t, publicKey)
	})

	t.Run("ECDSASECP256K1VerificationKey2019", func(t *testing.T) {
		t.Run("generated key", func(t *testing.T) {
			id := actual.ID
			id.Fragment = "1"
			privateKey, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err)

			vm, err := NewVerificationMethod(id, ssi.ECDSASECP256K1VerificationKey2019, actual.ID, privateKey.ToECDSA())
			require.NoError(t, err)

			publicKey, err := vm.PublicKey()
			require.NoError(t, err)
			require.NotNil(t, publicKey)
			asJWK, err := vm.JWK()
			require.NoError(t, err)
			require.NotNil(t, asJWK)
		})
		t.Run("static", func(t *testing.T) {
			// copied from an online did:web source
			const asJSON = `{
				"controller": "did:web:example.com",
				"id": "did:web:example.com#xCPeUKv-0t4TPSlRnk61AqIK-DtH-riOvyx_Udk65XA",
				"publicKeyJwk": {
					"kty": "EC",
					"x": "P_kEHfyV27kg5oxn1pzTTDAkNKqsH9QdfdADcKLlr4Y",
					"y": "GE0tU43W30xT-DKmF75uWCWSnXid3kKhnYZbdWhiguE",
					"crv": "secp256k1",
					"kid": "did:web:example.com#xCPeUKv-0t4TPSlRnk61AqIK-DtH-riOvyx_Udk65XA"
				},
				"type": "EcdsaSecp256k1VerificationKey2019"
        	}`
			vm := VerificationMethod{}
			err := json.Unmarshal([]byte(asJSON), &vm)
			require.NoError(t, err)

			publicKey, err := vm.PublicKey()
			require.NoError(t, err)
			require.NotNil(t, publicKey)
		})
	})

	t.Run("it can parse a jwk in a verification method", func(t *testing.T) {
		keyAsJWK, err := actual.Authentication[0].JWK()
		if !assert.NoError(t, err, "expected key to be converted to a jwk.key") {
			return
		}
		assert.Equal(t, "EC", keyAsJWK.KeyType().String())
	})

	t.Run("AddAssertionMethod", func(t *testing.T) {
		t.Run("it adds the method to assertionMethod once", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddAssertionMethod(method)
			doc.AddAssertionMethod(method)
			assert.Len(t, doc.AssertionMethod, 1)
			assert.Equal(t, doc.AssertionMethod[0].VerificationMethod, method)
		})
		t.Run("it adds the method to the verificationMethods once", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddAssertionMethod(method)
			doc.AddAssertionMethod(method)
			assert.Len(t, doc.VerificationMethod, 1)
			assert.Equal(t, doc.VerificationMethod[0], method)
		})
		t.Run("it sets the controller when not set", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddAssertionMethod(method)
			assert.Equal(t, method.Controller, *id123)
		})
		t.Run("it leaves the controller when already set", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method, Controller: *id456}
			doc.AddAssertionMethod(method)
			assert.Equal(t, method.Controller, *id456)
		})
	})

	t.Run("AddAuthenticationMethod", func(t *testing.T) {
		t.Run("it adds the method to AuthenticationMethod once", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddAuthenticationMethod(method)
			doc.AddAuthenticationMethod(method)
			assert.Len(t, doc.Authentication, 1)
		})
		t.Run("it adds the method to the AuthenticationMethods once", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddAuthenticationMethod(method)
			doc.AddAuthenticationMethod(method)
			assert.Len(t, doc.Authentication, 1)
			assert.Equal(t, doc.Authentication[0].VerificationMethod, method)
		})
		t.Run("it sets the controller when not set", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddAuthenticationMethod(method)
			assert.Equal(t, method.Controller, *id123)
		})
		t.Run("it leaves the controller when already set", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method, Controller: *id456}
			doc.AddAuthenticationMethod(method)
			assert.Equal(t, method.Controller, *id456)
		})
	})

	t.Run("AddKeyAgreement", func(t *testing.T) {
		t.Run("it adds the method to KeyAgreement once", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddKeyAgreement(method)
			doc.AddKeyAgreement(method)
			assert.Len(t, doc.KeyAgreement, 1)
			assert.Len(t, doc.VerificationMethod, 1)
		})
	})
	t.Run("AddCapabilityInvocation", func(t *testing.T) {
		t.Run("it adds the method to CapabilityInvocation once", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddCapabilityInvocation(method)
			doc.AddCapabilityInvocation(method)
			assert.Len(t, doc.CapabilityInvocation, 1)
			assert.Len(t, doc.VerificationMethod, 1)
		})
	})
	t.Run("AddCapabilityDelegation", func(t *testing.T) {
		t.Run("it adds the method to CapabilityDelegation once", func(t *testing.T) {
			doc := Document{ID: *id123}
			method := &VerificationMethod{ID: *id123Method}
			doc.AddCapabilityDelegation(method)
			doc.AddCapabilityDelegation(method)
			assert.Len(t, doc.CapabilityDelegation, 1)
			assert.Len(t, doc.VerificationMethod, 1)
		})
	})
}

func TestDocument_UnmarshallJSON(t *testing.T) {
	t.Run("resolving verificationRelationships", func(t *testing.T) {
		t.Run("authentication", func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "authentication":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#abc"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.NoError(t, err)
				assert.Equal(t, "did:example:123", doc.ID.String())
				assert.Equal(t, "did:example:123#abc", doc.Authentication[0].ID.String())
				assert.Equal(t, "did:example:123#abc", doc.VerificationMethod[0].ID.String())
			})
			t.Run("error - missing verificationMethod", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "authentication":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#def"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.EqualError(t, err, "unable to resolve all 'authentication' references: unable to resolve verificationMethod: did:example:123#abc")
			})
		})

		t.Run("assertionMethod", func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "assertionMethod":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#abc"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.NoError(t, err)
				assert.Equal(t, "did:example:123", doc.ID.String())
				assert.Equal(t, "did:example:123#abc", doc.AssertionMethod[0].ID.String())
				assert.Equal(t, "did:example:123#abc", doc.VerificationMethod[0].ID.String())
			})
			t.Run("error - missing verificationMethod", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "assertionMethod":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#def"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.EqualError(t, err, "unable to resolve all 'assertionMethod' references: unable to resolve verificationMethod: did:example:123#abc")
			})
		})

		t.Run("keyAgreement", func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "keyAgreement":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#abc"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.NoError(t, err)
				assert.Equal(t, "did:example:123", doc.ID.String())
				assert.Equal(t, "did:example:123#abc", doc.KeyAgreement[0].ID.String())
				assert.Equal(t, "did:example:123#abc", doc.VerificationMethod[0].ID.String())
			})
			t.Run("error - missing verificationMethod", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "keyAgreement":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#def"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.EqualError(t, err, "unable to resolve all 'keyAgreement' references: unable to resolve verificationMethod: did:example:123#abc")
			})
		})

		t.Run("capabilityInvocation", func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "capabilityInvocation":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#abc"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.NoError(t, err)
				assert.Equal(t, "did:example:123", doc.ID.String())
				assert.Equal(t, "did:example:123#abc", doc.CapabilityInvocation[0].ID.String())
				assert.Equal(t, "did:example:123#abc", doc.VerificationMethod[0].ID.String())
			})
			t.Run("error - missing verificationMethod", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "capabilityInvocation":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#def"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.EqualError(t, err, "unable to resolve all 'capabilityInvocation' references: unable to resolve verificationMethod: did:example:123#abc")
			})
		})

		t.Run("capabilityDelegation", func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "capabilityDelegation":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#abc"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.NoError(t, err)
				assert.Equal(t, "did:example:123", doc.ID.String())
				assert.Equal(t, "did:example:123#abc", doc.CapabilityDelegation[0].ID.String())
				assert.Equal(t, "did:example:123#abc", doc.VerificationMethod[0].ID.String())
			})
			t.Run("error - missing verificationMethod", func(t *testing.T) {
				docJSON := []byte(`{ "ID": "did:example:123", "capabilityDelegation":["did:example:123#abc"], "verificationMethod":[{"ID":"did:example:123#def"}]}`)
				doc := Document{}
				err := json.Unmarshal(docJSON, &doc)
				assert.EqualError(t, err, "unable to resolve all 'capabilityDelegation' references: unable to resolve verificationMethod: did:example:123#abc")
			})
		})
	})
}

func TestRoundTripMarshalling(t *testing.T) {
	testCases := []string{
		"did1",
	}

	for _, testCase := range testCases {
		t.Run(testCase, func(t *testing.T) {
			document, err := ParseDocument(string(test.ReadTestFile("test/" + testCase + ".json")))
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

	// Test to check if a newly created VerificationMethod is the same as a parsed one.
	t.Run("verification method marshalling", func(t *testing.T) {
		id123, _ := ParseDID("did:example:123")
		id123Method, _ := ParseDIDURL("did:example:123#abc-method1")
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		method, err := NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, *id123, pair.PublicKey)
		if !assert.NoError(t, err) {
			return
		}
		methodJson, err := json.Marshal(method)
		if !assert.NoError(t, err) {
			return
		}

		unmarshalledMethod := &VerificationMethod{}
		err = json.Unmarshal(methodJson, unmarshalledMethod)
		assert.Equal(t, method, unmarshalledMethod,
			"expected new created method to be equal to a marshalled and unmarshalled one")
	})
}

func TestDocument_RemoveVerificationMethod(t *testing.T) {
	id123, _ := ParseDID("did:example:123")

	t.Run("ok", func(t *testing.T) {
		doc := Document{}
		vm := &VerificationMethod{ID: *id123}
		doc.AddAssertionMethod(vm)
		doc.AddAuthenticationMethod(vm)
		doc.AddCapabilityDelegation(vm)
		doc.AddCapabilityInvocation(vm)
		doc.AddKeyAgreement(vm)

		doc.RemoveVerificationMethod(*id123)

		assert.Len(t, doc.VerificationMethod, 0,
			"the verification method should have been deleted")
		assert.Nil(t, doc.AssertionMethod.FindByID(*id123))
		assert.Nil(t, doc.Authentication.FindByID(*id123))
		assert.Nil(t, doc.CapabilityDelegation.FindByID(*id123))
		assert.Nil(t, doc.CapabilityInvocation.FindByID(*id123))
		assert.Nil(t, doc.KeyAgreement.FindByID(*id123))
	})

	t.Run("not found", func(t *testing.T) {
		doc := Document{}

		doc.RemoveVerificationMethod(*id123)

		assert.Len(t, doc.VerificationMethod, 0)
	})
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

func TestNewVerificationMethod(t *testing.T) {
	t.Run("Ed25519VerificationKey2018", func(t *testing.T) {
		id, _ := ParseDID("did:example:123")
		expectedKey, _, _ := ed25519.GenerateKey(rand.Reader)
		vm, err := NewVerificationMethod(*id, ssi.ED25519VerificationKey2018, *id, expectedKey)
		require.NoError(t, err)
		assert.Equal(t, ssi.ED25519VerificationKey2018, vm.Type)
		assert.NotEmpty(t, vm.PublicKeyMultibase)
		assert.Empty(t, vm.PublicKeyBase58)
		// Unmarshal, check it's equal to the input key
		actualKey, err := vm.PublicKey()
		require.NoError(t, err)
		assert.Equal(t, expectedKey, actualKey)
	})
}

func TestVerificationMethod_UnmarshalJSON(t *testing.T) {
	t.Run("both publicKeyJWK and publicKeyMultibase present", func(t *testing.T) {
		input, _ := json.Marshal(VerificationMethod{
			ID:                 MustParseDIDURL("did:example:123#key-1"),
			Controller:         MustParseDIDURL("did:example:123"),
			PublicKeyJwk:       map[string]interface{}{"kty": "EC"},
			PublicKeyMultibase: "foobar",
		})
		actual := VerificationMethod{}
		err := json.Unmarshal(input, &actual)
		assert.EqualError(t, err, "only one of publicKeyJWK, publicKeyBase58 and publicKeyMultibase can be present")
	})
	t.Run("all of publicKeyJWK, publicKeyMultibase and publicKeyBase58 are present", func(t *testing.T) {
		input, _ := json.Marshal(VerificationMethod{
			ID:                 MustParseDIDURL("did:example:123#key-1"),
			Controller:         MustParseDIDURL("did:example:123"),
			PublicKeyJwk:       map[string]interface{}{"kty": "EC"},
			PublicKeyMultibase: "foobar",
			PublicKeyBase58:    "foobar",
		})
		actual := VerificationMethod{}
		err := json.Unmarshal(input, &actual)
		assert.EqualError(t, err, "only one of publicKeyJWK, publicKeyBase58 and publicKeyMultibase can be present")
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
	t.Run("ok", func(t *testing.T) {
		type targetType struct {
			Value string
		}
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
	t.Run("single value", func(t *testing.T) {
		input := Service{}
		json.Unmarshal([]byte(`{
		  "id":"did:example:123#linked-domain",
		  "type":"custom",
		  "serviceEndpoint": "http://awesome-url"
		}`), &input)
		var target string
		err := input.UnmarshalServiceEndpoint(&target)
		assert.NoError(t, err)
		assert.Equal(t, "http://awesome-url", target)
	})
}

func Test_VerificationMethods(t *testing.T) {
	id123, _ := ParseDID("did:example:123")
	id456, _ := ParseDID("did:example:456")
	unknownID, _ := ParseDID("did:example:abc")

	t.Run("Remove", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			vms := VerificationMethods{
				&VerificationMethod{ID: *id123},
				&VerificationMethod{ID: *id456},
			}
			vms.remove(*id456)
			assert.Len(t, vms, 1,
				"the verification method should have been deleted")
			assert.Equal(t, *id123, vms[0].ID)
		})

		t.Run("not found", func(t *testing.T) {
			vms := VerificationMethods{
				&VerificationMethod{ID: *id123},
				&VerificationMethod{ID: *id456},
			}
			vms.remove(*unknownID)
			assert.Len(t, vms, 2)
		})
	})

	t.Run("FindByID", func(t *testing.T) {
		t.Run("found", func(t *testing.T) {
			vms := VerificationMethods{
				&VerificationMethod{ID: *id123},
				&VerificationMethod{ID: *id456},
			}
			vm := vms.FindByID(*id123)
			assert.Equal(t, vm.ID, *id123)
		})
		t.Run("unknown", func(t *testing.T) {
			vms := VerificationMethods{
				&VerificationMethod{ID: *id123},
				&VerificationMethod{ID: *id456},
			}
			vm := vms.FindByID(*unknownID)
			assert.Nil(t, vm)
		})

	})

	t.Run("Add", func(t *testing.T) {
		t.Run("adds non existing", func(t *testing.T) {
			vms := VerificationMethods{}
			vms.Add(&VerificationMethod{ID: *id123})
			assert.Len(t, vms, 1)
		})
		t.Run("does not add vm with duplicate id", func(t *testing.T) {
			vms := VerificationMethods{
				&VerificationMethod{ID: *id123},
			}
			vms.Add(&VerificationMethod{ID: *id123})
			assert.Len(t, vms, 1)
		})
	})
}

func TestVerificationRelationships(t *testing.T) {
	id123, _ := ParseDID("did:example:123")
	id456, _ := ParseDID("did:example:456")
	unknownID, _ := ParseDID("did:example:abc")

	t.Run("Remove", func(t *testing.T) {
		t.Run("known value", func(t *testing.T) {
			vmRels := VerificationRelationships{
				VerificationRelationship{VerificationMethod: &VerificationMethod{ID: *id123}},
			}
			removedRel := vmRels.Remove(*id123)
			assert.Empty(t, vmRels,
				"expected vmRels to be empty after removing the only element")
			assert.Equal(t, removedRel.ID, *id123)
		})

		t.Run("known value", func(t *testing.T) {
			vmRels := VerificationRelationships{
				VerificationRelationship{VerificationMethod: &VerificationMethod{ID: *id123}},
			}
			removedRel := vmRels.Remove(*unknownID)
			assert.Nil(t, removedRel,
				"expected Remove not to return a value when trying to remove an unknown value")
			assert.Len(t, vmRels, 1,
				"expected vmRels to contain all elements after failed removal")
		})
	})

	t.Run("FindByID", func(t *testing.T) {
		vmRels := VerificationRelationships{
			VerificationRelationship{reference: *id123, VerificationMethod: &VerificationMethod{ID: *id123}},
			VerificationRelationship{VerificationMethod: &VerificationMethod{ID: *id456}},
		}

		t.Run("for a known value with reference", func(t *testing.T) {
			foundValue := vmRels.FindByID(*id123)
			assert.NotNil(t, foundValue,
				"expected value could be found")

			assert.Equal(t, foundValue.ID, *id123,
				"expected ID of found value to match searched ID")
		})

		t.Run("for a known referenced value", func(t *testing.T) {
			foundValue := vmRels.FindByID(*id456)
			assert.NotNil(t, foundValue,
				"expected value could be found")

			assert.Equal(t, foundValue.ID, *id456,
				"expected ID of found value to match searched ID")
		})

		t.Run("for an unknown value", func(t *testing.T) {
			foundValue := vmRels.FindByID(*unknownID)
			assert.Nil(t, foundValue,
				"expected value could not be found")

		})
	})
	t.Run("Add", func(t *testing.T) {
		t.Run("it adds", func(t *testing.T) {
			rels := VerificationRelationships{}
			rels.Add(&VerificationMethod{ID: *id123})
			assert.Len(t, rels, 1)
			assert.Equal(t, rels[0].ID, *id123)
		})

		t.Run("it does not add when already present", func(t *testing.T) {
			rels := VerificationRelationships{}
			rels.Add(&VerificationMethod{ID: *id123})
			rels.Add(&VerificationMethod{ID: *id123})
			assert.Len(t, rels, 1)
			assert.Equal(t, rels[0].ID, *id123)
		})
	})
}

func TestDocument_ResolveEndpointURL(t *testing.T) {
	jsonDoc := `
{
	"@context": ["https://www.w3.org/ns/did/v1"],
	"id": "did:web:identity.foundation",
	"controller": ["did:web:example.org"],
	"service": [
		{
		  "id":"did:example:123#linked-domain",
		  "type":"custom",
		  "serviceEndpoint": "https://example.com"
		}
	]
}`
	doc := Document{}
	json.Unmarshal([]byte(jsonDoc), &doc)

	t.Run("ok", func(t *testing.T) {
		endpointID, endpointURL, err := doc.ResolveEndpointURL("custom")

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "https://example.com", endpointURL)
		assert.Equal(t, "did:example:123#linked-domain", endpointID.String())
	})

	t.Run("no services match", func(t *testing.T) {
		doc := Document{}
		json.Unmarshal([]byte(jsonDoc), &doc)
		doc.Service = []Service{}

		_, _, err := doc.ResolveEndpointURL("custom")
		assert.EqualError(t, err, "service not found (did=did:web:identity.foundation, type=custom)")
	})

	t.Run("multiple services match", func(t *testing.T) {
		jsonService :=
			`{
	"id":"did:example:123#linked-domain",
	"type":"custom",
	"serviceEndpoint": "https://example.com"
}`
		s := Service{}
		_ = json.Unmarshal([]byte(jsonService), &s)
		doc := Document{}
		json.Unmarshal([]byte(jsonDoc), &doc)
		doc.Service = append(doc.Service, s)

		_, _, err := doc.ResolveEndpointURL("custom")
		assert.EqualError(t, err, "multiple services found (did=did:web:identity.foundation, type=custom)")
	})
	t.Run("serviceEndpoint is not a single string", func(t *testing.T) {
		jsonService :=
			`{
	"id":"did:example:123#linked-domain",
	"type":"custom",
	"serviceEndpoint": {"sub": "https://example.com"}
}`
		s := Service{}
		_ = json.Unmarshal([]byte(jsonService), &s)
		doc := Document{}
		json.Unmarshal([]byte(jsonDoc), &doc)
		doc.Service = []Service{s}

		_, _, err := doc.ResolveEndpointURL("custom")
		assert.EqualError(t, err, "unable to unmarshal single URL from service (id=did:example:123#linked-domain): json: cannot unmarshal object into Go value of type string")
	})
}

func TestDocument_IsController(t *testing.T) {
	id123, _ := ParseDID("did:example:123")
	id456, _ := ParseDID("did:example:456")

	t.Run("no controllers", func(t *testing.T) {
		assert.False(t, Document{}.IsController(*id123))
	})
	t.Run("empty input", func(t *testing.T) {
		assert.False(t, Document{}.IsController(DID{}))
	})
	t.Run("is a controller", func(t *testing.T) {
		assert.True(t, Document{Controller: []DID{*id123, *id456}}.IsController(*id123))
	})
	t.Run("is not a controller", func(t *testing.T) {
		assert.False(t, Document{Controller: []DID{*id456}}.IsController(*id123))
	})
}
