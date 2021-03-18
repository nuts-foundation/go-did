package did


import (
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestW3CSpecValidator(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, W3CSpecValidator{}.Validate(document()))
	})
	t.Run("context is missing DIDv1", func(t *testing.T) {
		input := document()
		input.Context = []ssi.URI{}
		assertIsError(t, ErrInvalidContext, W3CSpecValidator{}.Validate(input))
	})
	t.Run("document is missing ID", func(t *testing.T) {
		input := document()
		input.ID = DID{}
		assertIsError(t, ErrInvalidID, W3CSpecValidator{}.Validate(input))
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
		t.Fatalf("\ngot error: %v\nwanted error: %v", actual, expected)
	}
}

func document() Document {
	did, _ := ParseDID("did:test:12345")
	return Document{
		Context:            []ssi.URI{DIDContextV1URI()},
		ID:                 *did,
	}
}

type funcValidator struct {
	fn func(document Document) error
}

func (f funcValidator) Validate(document Document) error {
	return f.fn(document)
}

