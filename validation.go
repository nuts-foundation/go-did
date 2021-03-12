package did

import (
	"errors"
	"fmt"
)

var ErrDIDDocumentInvalid = errors.New("DID Document validation failed")
var ErrInvalidContext = errors.New("invalid context")
var ErrInvalidID = errors.New("invalid ID")

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
