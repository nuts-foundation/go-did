package did

import (
	"errors"
	"testing"
)

func assertIsError(t *testing.T, expected error, actual error) {
	if !errors.Is(actual, expected) {
		t.Fatalf("\ngot error: %v\nwanted error: %v", actual, expected)
	}
}

func TestValidateDocument(t *testing.T) {
	t.Run("context is missing DIDv1", func(t *testing.T) {
		input := document()
		input.Context = []URI{}
		assertIsError(t, ErrInvalidContext, ValidateDocument(input))
	})
	t.Run("document is missing ID", func(t *testing.T) {
		input := document()
		input.ID = DID{}
		assertIsError(t, ErrInvalidID, ValidateDocument(input))
	})

}

func document() Document {
	did, _ := ParseDID("did:test:12345")
	return Document{
		Context:            []URI{DIDContextV1URI()},
		ID:                 *did,
	}
}
