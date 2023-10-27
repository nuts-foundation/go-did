package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestW3CSpecValidator(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, W3CSpecValidator{}.Validate(document()))
	})
	t.Run("base", func(t *testing.T) {
		didUrl, err := ParseDIDURL("did:example:123#fragment")
		if !assert.NoError(t, err) {
			return
		}
		t.Run("context is missing DIDv1", func(t *testing.T) {
			input := document()
			input.Context = []interface{}{
				"someting-else",
				map[string]interface{}{
					"@base": "did:example:123",
				},
			}
			assertIsError(t, ErrInvalidContext, W3CSpecValidator{}.Validate(input))
		})
		t.Run("invalid ID - is empty", func(t *testing.T) {
			input := document()
			input.ID = DID{}
			assertIsError(t, ErrInvalidID, W3CSpecValidator{}.Validate(input))
		})
		t.Run("invalid ID - is URL", func(t *testing.T) {
			input := document()
			input.ID = *didUrl
			assertIsError(t, ErrInvalidID, W3CSpecValidator{}.Validate(input))
		})

		t.Run("invalid controller - is empty", func(t *testing.T) {
			input := document()
			input.Controller = append(input.Controller, DID{})
			assertIsError(t, ErrInvalidController, W3CSpecValidator{}.Validate(input))
		})

		t.Run("invalid controller - is URL", func(t *testing.T) {
			input := document()
			input.Controller = append(input.Controller, *didUrl)
			assertIsError(t, ErrInvalidController, W3CSpecValidator{}.Validate(input))
		})
	})
	t.Run("verificationMethod", func(t *testing.T) {
		t.Run("invalid ID", func(t *testing.T) {
			input := document()
			input.VerificationMethod[0].ID = DID{}
			assertIsError(t, ErrInvalidVerificationMethod, W3CSpecValidator{}.Validate(input))
		})
		t.Run("invalid controller", func(t *testing.T) {
			input := document()
			input.VerificationMethod[0].Controller = DID{}
			assertIsError(t, ErrInvalidVerificationMethod, W3CSpecValidator{}.Validate(input))
		})
		t.Run("invalid type", func(t *testing.T) {
			input := document()
			input.VerificationMethod[0].Type = " "
			assertIsError(t, ErrInvalidVerificationMethod, W3CSpecValidator{}.Validate(input))
		})
	})
	t.Run("authentication", func(t *testing.T) {
		t.Run("invalid ID", func(t *testing.T) {
			input := document()
			// Make copy first because it is a reference instead of embedded
			vm := *input.VerificationMethod[0]
			input.Authentication[0] = VerificationRelationship{VerificationMethod: &vm}
			// Then alter
			input.Authentication[0].ID = DID{}
			assertIsError(t, ErrInvalidAuthentication, W3CSpecValidator{}.Validate(input))
		})
		t.Run("invalid controller", func(t *testing.T) {
			input := document()
			// Make copy first because it is a reference instead of embedded
			vm := *input.VerificationMethod[0]
			input.Authentication[0] = VerificationRelationship{VerificationMethod: &vm}
			// Then alter
			input.Authentication[0].Controller = DID{}
			assertIsError(t, ErrInvalidAuthentication, W3CSpecValidator{}.Validate(input))
		})
	})
	t.Run("service", func(t *testing.T) {
		t.Run("invalid ID", func(t *testing.T) {
			input := document()
			input.Service[0].ID = ssi.URI{}
			assertIsError(t, ErrInvalidService, W3CSpecValidator{}.Validate(input))
		})
		t.Run("invalid type", func(t *testing.T) {
			input := document()
			input.Service[0].Type = " "
			assertIsError(t, ErrInvalidService, W3CSpecValidator{}.Validate(input))
		})
		t.Run("endpoint is nil", func(t *testing.T) {
			input := document()
			input.Service[0].ServiceEndpoint = nil
			assertIsError(t, ErrInvalidService, W3CSpecValidator{}.Validate(input))
		})
		t.Run("endpoint is bool", func(t *testing.T) {
			input := document()
			input.Service[0].ServiceEndpoint = false
			assertIsError(t, ErrInvalidService, W3CSpecValidator{}.Validate(input))
		})
		t.Run("endpoint is numeric", func(t *testing.T) {
			input := document()
			input.Service[0].ServiceEndpoint = 5
			assertIsError(t, ErrInvalidService, W3CSpecValidator{}.Validate(input))
		})
		t.Run("ok - endpoint is slice", func(t *testing.T) {
			input := document()
			input.Service[0].ServiceEndpoint = []interface{}{"a", "b"}
			assert.NoError(t, W3CSpecValidator{}.Validate(input))
		})
		t.Run("ok - endpoint is slice", func(t *testing.T) {
			input := document()
			input.Service[0].ServiceEndpoint = []interface{}{"a", "b"}
			assert.NoError(t, W3CSpecValidator{}.Validate(input))
		})
		t.Run("ok - endpoint is map (string/interface)", func(t *testing.T) {
			input := document()
			input.Service[0].ServiceEndpoint = map[string]interface{}{}
			assert.NoError(t, W3CSpecValidator{}.Validate(input))
		})
	})
}

func TestMultiValidator(t *testing.T) {
	t.Run("no validators", func(t *testing.T) {
		assert.NoError(t, MultiValidator{}.Validate(document()))
	})
	t.Run("no errors", func(t *testing.T) {
		v := W3CSpecValidator{}
		assert.NoError(t, MultiValidator{Validators: []Validator{v, v}}.Validate(document()))
	})
	t.Run("returns first", func(t *testing.T) {
		v1 := W3CSpecValidator{}
		v2 := funcValidator{fn: func(_ Document) error {
			return errors.New("failed")
		}}
		assert.Error(t, MultiValidator{Validators: []Validator{v2, v1}}.Validate(document()))
	})
	t.Run("returns second", func(t *testing.T) {
		v1 := W3CSpecValidator{}
		v2 := funcValidator{fn: func(_ Document) error {
			return errors.New("failed")
		}}
		assert.Error(t, MultiValidator{Validators: []Validator{v1, v2}}.Validate(document()))
	})
}

func assertIsError(t *testing.T, expected error, actual error) {
	if !errors.Is(actual, expected) {
		t.Errorf("\ngot error: %v\nwanted error: %v", actual, expected)
	}
}

func document() Document {
	did, _ := ParseDID("did:test:12345")

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyID := *did
	keyID.Fragment = "key-1"
	vm, _ := NewVerificationMethod(keyID, ssi.JsonWebKey2020, *did, privateKey.Public())

	serviceID := *did
	serviceID.Fragment = "service-1"
	doc := Document{
		Context: []interface{}{
			DIDContextV1URI(),
			map[string]interface{}{
				"@base": "did:example:12345",
			},
		},
		ID:                 *did,
		Controller:         []DID{*did},
		VerificationMethod: []*VerificationMethod{vm},
		Service: []Service{{
			ID:              serviceID.URI(),
			Type:            "awesome-service",
			ServiceEndpoint: "tcp://awesome-service",
		}},
	}
	doc.AddAuthenticationMethod(vm)
	doc.AddAssertionMethod(vm)
	return doc
}

type funcValidator struct {
	fn func(document Document) error
}

func (f funcValidator) Validate(document Document) error {
	return f.fn(document)
}
