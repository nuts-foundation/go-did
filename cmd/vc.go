package main

func verifiableCredential() ModelDefinition {
	return ModelDefinition{
		Name:                    "VerifiableCredential",
		SupportJWTSerialization: true,
		SupportLDSerialization:  true,
		Imports: []string{
			`"github.com/nuts-foundation/go-did/v1/ld"`,
			`"time"`,
			`"net/url"`,
		},
		Fields: []FieldDefinition{
			{
				Name:     "Context",
				GoType:   "[]interface{}",
				Required: true,
				IRI:      "@context",
				JWTClaim: "vc.@context",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#context-urls",
			},
			{
				Name:     "ID",
				GoType:   "*url.URL",
				IRI:      "@id",
				JWTClaim: "jti",
			},
			{
				Name:     "Type",
				GoType:   "[]string",
				Required: true,
				IRI:      "@type",
				JWTClaim: "vc.@type",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#types",
			},
			{
				Name:     "Issuer",
				GoType:   "Issuer",
				Required: true,
				IRI:      "https://www.w3.org/2018/credentials#issuer",
				JWTClaim: "iss",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#issuer",
			},
			{
				Name:     "IssuanceDate",
				GoType:   "time.Time",
				Required: true,
				IRI:      "https://www.w3.org/2018/credentials#issuanceDate",
				JWTClaim: "nbf",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#issuance",
			},
			{
				Name:     "ExpirationDate",
				GoType:   "time.Time",
				Required: false,
				IRI:      "https://www.w3.org/2018/credentials#expirationDate",
				JWTClaim: "exp",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#expiration",
			},
			{
				Name:     "CredentialSubject",
				GoType:   "[]CredentialSubject",
				Required: true,
				IRI:      "https://www.w3.org/2018/credentials#credentialSubject",
				JWTClaim: "vc.credentialSubject",
				DocLink:  "https://www.w3.org/TR/vc-data-model/#credential-subject",
			},
		},
	}
}

func issuer() ModelDefinition {
	return ModelDefinition{
		Name: "Issuer",
		Imports: []string{
			`"github.com/nuts-foundation/go-did/v1/ld"`,
			`"net/url"`,
		},
		SupportLDSerialization:  true,
		SupportJWTSerialization: true,
		Fields: []FieldDefinition{
			{
				Name:     "ID",
				GoType:   "*url.URL",
				IRI:      "@id",
				Required: true,
			},
		},
	}
}

func credentialSubject() ModelDefinition {
	return ModelDefinition{
		Name: "CredentialSubject",
		Imports: []string{
			`"github.com/nuts-foundation/go-did/v1/ld"`,
			`"net/url"`,
		},
		SupportLDSerialization:  true,
		SupportJWTSerialization: true,
		Fields: []FieldDefinition{
			{
				Name:   "ID",
				GoType: "*url.URL",
				IRI:    "@id",
			},
		},
	}
}
