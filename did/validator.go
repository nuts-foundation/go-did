package did

import (
	"errors"
	"fmt"
)

// ErrDIDDocumentInvalid indicates DID Document validation failed
var ErrDIDDocumentInvalid = errors.New("DID Document validation failed")
// ErrInvalidContext indicates the DID Document's `@context` is invalid
var ErrInvalidContext = errors.New("invalid context")
// ErrInvalidID indicates the DID Document's `id` is invalid
var ErrInvalidID = errors.New("invalid ID")

// Validator defines functions for validating a DID document.
type Validator interface {
	// Validate validates a DID document. It returns the first validation error is finds wrapped in ErrDIDDocumentInvalid.
	Validate(document Document) error
}

// MultiValidator is a validator that executes zero or more validators. It returns the first validation error it encounters.
type MultiValidator struct {
	Validators []Validator
}

func (m MultiValidator) Validate(document Document) error {
	for _, validator := range m.Validators {
		if err := validator.Validate(document); err != nil {
			return err
		}
	}
	return nil
}

// W3CSpecValidator validates a DID document according to the W3C DID Core Data Model specification (https://www.w3.org/TR/did-core/).
type W3CSpecValidator struct {

}

func (w W3CSpecValidator) Validate(document Document) error {
	// Verify @context
	if !containsContext(document, DIDContextV1) {
		return validationError(ErrInvalidContext)
	}
	// Verify ID
	if document.ID.Empty() {
		return validationError(ErrInvalidID)
	}
	return nil
}

func containsContext(document Document, ctx string) bool {
	for _, curr := range document.Context {
		if curr.String() == ctx {
			return true
		}
	}
	return false
}

func validationError(validationErr error) error {
	return fmt.Errorf("%s: %w", ErrDIDDocumentInvalid.Error(), validationErr)
}