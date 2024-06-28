package main

func didDocument() ModelDefinition {
	return ModelDefinition{
		Name: "Document",
		Imports: []string{
			`"github.com/nuts-foundation/go-did/v1/ld"`,
			`ssi "github.com/nuts-foundation/go-did"`,
			`"github.com/nuts-foundation/go-did/did"`,
			`"github.com/nuts-foundation/go-did/v1/ld"`,
		},
		Fields: []FieldDefinition{
			{
				Name:     "ID",
				JSONName: "id",
				GoType:   "DID",
				Required: true,
			},
			{
				Name:     "AlsoKnownAs",
				JSONName: "alsoKnownAs",
				GoType:   "[]ssi.URI",
			},
			{
				Name:     "VerificationMethod",
				JSONName: "verificationMethod",
				GoType:   "VerificationMethods",
			},
			{
				Name:     "Authentication",
				JSONName: "authentication",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "AssertionMethod",
				JSONName: "assertionMethod",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "KeyAgreement",
				JSONName: "keyAgreement",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "CapabilityInvocation",
				JSONName: "capabilityInvocation",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "CapabilityDelegation",
				JSONName: "capabilityDelegation",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "Service",
				JSONName: "service",
				GoType:   "[]Service",
			},
		},
	}
}
