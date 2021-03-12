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

// ValidateDocument validates the given DID Document. If validation fails, it returns an error describing what's invalid,
// wrapped in ErrDIDDocumentInvalid.
func ValidateDocument(document Document) error {
	validationError := func(validationErr error) error {
		return fmt.Errorf("%s: %w", ErrDIDDocumentInvalid.Error(), validationErr)
	}
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
