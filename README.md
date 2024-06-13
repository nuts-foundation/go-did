
# github.com/nuts-foundation/go-did
[![Go Reference](https://pkg.go.dev/badge/github.com/nuts-foundation/go-did.svg)](https://pkg.go.dev/github.com/nuts-foundation/go-did)
[![Maintainability](https://api.codeclimate.com/v1/badges/4b4c812605d5c4f5ba3f/maintainability)](https://codeclimate.com/github/nuts-foundation/go-did/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/4b4c812605d5c4f5ba3f/test_coverage)](https://codeclimate.com/github/nuts-foundation/go-did/test_coverage)

A library to parse and generate W3C [DID Documents](https://www.w3.org/TR/did-core/) and W3C [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/).

## Example usage
Note on parsing: in earlier versions, DID documents, credentials and presentations were parsed using `UnmarshalJSON`.
Now, `ParseDocument()`, `ParseVerifiableCredential()` and `ParseVerifiablePresentation()` should be used instead: they better support VCs and VPs in JWT format.

### Parsing a DID document
```go
didDoc, err := did.ParseDocument(didDocJson)
if err != nil {
    panic(err)
}
// do something with didDoc
````

### Creating a DID document
Creation of a simple DID Document which is its own controller and contains an AssertionMethod.
```go
didID, err := did.ParseDID("did:example:123")

// Empty did document:
doc := &did.Document{
    Context:            []did.URI{did.DIDContextV1URI()},
    ID:                 *didID,
}

// Add an assertionMethod
keyID, _ := did.ParseDIDURL("did:example:123#key-1")

keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
verificationMethod, err := did.NewVerificationMethod(*keyID, did.JsonWebKey2020, did.DID{}, keyPair.Public())

// This adds the method to the VerificationMethod list and stores a reference to the assertion list
doc.AddAssertionMethod(verificationMethod)

didJson, _ := json.MarshalIndent(doc, "", "  ")
fmt.Println(string(didJson))
```

Outputs:
```json
{
  "assertionMethod": [
    "did:example:123#key-1"
  ],
  "@context": "https://www.w3.org/ns/did/v1",
  "controller": "did:example:123",
  "id": "did:example:123",
  "verificationMethod": [
    {
      "controller": "did:example:123",
      "id": "did:example:123#key-1",
      "publicKeyJwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "UANQ8pgvJT33JbrnwMiu1L1JCGQFOEm1ThaNAJcFrWA=",
        "y": "UWm6q5n1iXyeCJLMGDInN40bkkKr8KkoTWDqJBZQXRo="
      },
      "type": "JsonWebKey2020"
    }
  ]
}
```

### Parsing Verifiable Credentials and Verifiable Presentations
The library supports parsing of Verifiable Credentials and Verifiable Presentations in JSON-LD, and JWT proof format.
Use `ParseVerifiableCredential(raw string)` and `ParseVerifiablePresentation(raw string)`.

## Supported key types

- `JsonWebKey2020`
- `Ed25519VerificationKey2018`
- `EcdsaSecp256k1VerificationKey2019` (pass build tag to enable: `-tags=jwx_es256k`)

## Installation
```
go get github.com/nuts-foundation/go-did
```

## Testing

```shell
go test ./... -tags=jwx_es256k
```

## State of the library
We keep the API stable, breaking changes will only be introduced in new major versions.
