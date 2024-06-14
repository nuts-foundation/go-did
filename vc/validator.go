package vc

import (
	"crypto"
	"github.com/nuts-foundation/go-did/did"
	"time"
)

/*

Usage:

credential.Verify(
  WithVerifyJSONSchema(schemaLoader),
  WithVerifySignature(keyResolver),
  WithVerifyExpiration(clock, maxAcceptableClockSkew),
  WithVerifyStatusList2021(credentialLoader),
)

presentation.Verify(
  WithVerifyJSONSchema(schemaLoader),
  WithVerifySignature(keyResolver),
  WithVerifyExpiration(clock, maxAcceptableClockSkew),
  WithVerifyStatusList2021(credentialLoader),
  WithPresenterIsCredentialSubject(),
)

These instantiate the appropriate verifier (PresentationVerifier or CredentialVerifier) and call Verify(...) on it.
*/

type Verifier interface {
	Verify(options ...VerifierOption) error
}

type VerifierOption func()

// WithVerifyJSONSchema configures the verifier to check the credential/presentation contents against the given JSON schema.
func WithVerifyJSONSchema(schemaLoader interface{}) VerifierOption {
	// TODO
	return nil
}

// WithVerifySignature configures the verifier to check the proof signature.
func WithVerifySignature(keyResolver KeyResolver) VerifierOption {
	// TODO
	return nil
}

// WithVerifyExpiration configures the verifier to check the expiration date.
func WithVerifyExpiration(clock time.Time, maxAcceptableClockSkew time.Duration) VerifierOption {
	// TODO
	return nil
}

// WithVerifyStatusList2021 configures the verifier to check the credential status according to StatusList2021.
// The status credential is resolved using the given credential loader.
func WithVerifyStatusList2021(credentialLoader func(credentialURI string) (*VerifiableCredential, error)) VerifierOption {
	// TODO
	return nil
}

// WithPresenterIsCredentialSubject configures the verifier to check that proof signature of the Verifiable Presentation
// was generated with a key that belongs to the credential subject contained in the Verifiable Presentation.
// All credentials in the Verifiable Presentation must have the same credential subject DID.
func WithPresenterIsCredentialSubject() VerifierOption {
	// TODO
	return nil
}

type CredentialVerifier interface {
	Verify(credential VerifiableCredential, options ...VerifierOption) error
}

type PresentationVerifier interface {
	Verify(presentation VerifiablePresentation, options ...VerifierOption) error
}

// KeyResolver resolves keys for checking proof signatures.
type KeyResolver interface {
	// Resolve resolves a key for the given key ID.
	Resolve(keyURI string) (crypto.PublicKey, error)
}

var _ KeyResolver = DIDKeyResolver{}

// DIDKeyResolver implements the KeyResolver interface that resolves keys from DID documents.
// Key URIs are expected to be DID URLs.
type DIDKeyResolver struct {
	Resolver did.Resolver
}

func (D DIDKeyResolver) Resolve(keyURI string) (crypto.PublicKey, error) {
	panic("implement me")
}
