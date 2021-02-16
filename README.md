
# github.com/nuts-foundation/go-did [![Nuts](https://circleci.com/gh/nuts-foundation/go-did.svg?style=svg)](https://circleci.com/gh/nuts-foundation/go-did) [![Go Reference](https://pkg.go.dev/badge/github.com/nuts-foundation/go-did.svg)](https://pkg.go.dev/github.com/nuts-foundation/go-did)

A library to parse and generate W3C DID Documents.

## Example usage:
Creation of a simple DID Document which is its own controller and contains an AssertionMethod.
```go
didID, err := did.ParseDID("did:example:123")
if err != nil {
    panic(err)
}

doc := &did.Document{
    Context:            []did.URI{did.DIDContextV1URI()},
    ID:                 *didID,
    Controller:         []did.DID{*didID},
}

keyID, err := did.ParseDID(didID.String() + "#key-1")
if err != nil {
    panic(err)
}

keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
    panic(err)
}
verificationMethod, err := did.NewVerificationMethod(*keyID, did.JsonWebKey2020, did.DID{}, keyPair.Public())

doc.AddAssertionMethod(verificationMethod)

didJson, _ := json.MarshalIndent(doc, "", "  ")
fmt.Print(string(didJson))
```
Outputs:
```json
{
  "assertionMethod": [
    "did:example:123#key-1"
  ],
  "context": "https://www.w3.org/ns/did/v1",
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

## Installation
```
go get github.com/nuts-foundation/go-did
```

## State of the library
Currently, the library is under development. The api can change without notice.
Checkout the issues and PRs to be informed about any development.