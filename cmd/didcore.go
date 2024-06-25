package main

func didDocument() TypeDefinition {
	return TypeDefinition{
		Name: "Document",
		Fields: []FieldDefinition{
			{
				Name:     "Context",
				JSONName: "@context",
				GoType:   "[]interface",
			},
			{
				Name:     "ID",
				JSONName: "id",
				GoType:   "DID",
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
