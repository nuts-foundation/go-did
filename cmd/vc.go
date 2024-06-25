package main

func verifiableCredential() TypeDefinition {
	return TypeDefinition{
		Name: "VerifiableCredential",
		Fields: []FieldDefinition{
			{
				Name:     "Type",
				GoType:   "[]string",
				Required: true,
				IRI:      "@type",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#types",
			},
			{
				Name:     "Issuer",
				GoType:   "ld.IDObject",
				Required: true,
				IRI:      "https://www.w3.org/2018/credentials#issuer",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#issuer",
			},
			{
				Name:     "IssuanceDate",
				GoType:   "time.Time",
				Required: true,
				IRI:      "https://www.w3.org/2018/credentials#issuanceDate",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#issuance",
			},
			{
				Name:     "ExpirationDate",
				GoType:   "time.Time",
				Required: false,
				IRI:      "https://www.w3.org/2018/credentials#expirationDate",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#expiration",
			},
			{
				Name:     "CredentialSubject",
				GoType:   "[]ld.Object",
				Required: true,
				IRI:      "https://www.w3.org/2018/credentials#credentialSubject",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#credential-subject",
			},
		},
	}
}
