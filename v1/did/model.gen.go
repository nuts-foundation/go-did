package did


import (
	"github.com/nuts-foundation/go-did/v1/ld"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/v1/ld"
)

type Document interface {
	// ID as defined by 
	ID() DID
	// AlsoKnownAs as defined by 
	AlsoKnownAs() (bool, []ssi.URI)
	// VerificationMethod as defined by 
	VerificationMethod() (bool, VerificationMethods)
	// Authentication as defined by 
	Authentication() (bool, VerificationRelationships)
	// AssertionMethod as defined by 
	AssertionMethod() (bool, VerificationRelationships)
	// KeyAgreement as defined by 
	KeyAgreement() (bool, VerificationRelationships)
	// CapabilityInvocation as defined by 
	CapabilityInvocation() (bool, VerificationRelationships)
	// CapabilityDelegation as defined by 
	CapabilityDelegation() (bool, VerificationRelationships)
	// Service as defined by 
	Service() (bool, []Service)
}

