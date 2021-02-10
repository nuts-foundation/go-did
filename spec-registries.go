package did

import "net/url"

const DIDContextV1 = "https://www.w3.org/ns/did/v1"

func DIDContextV1URI() URI {
	if underlyingURL, err := url.Parse(DIDContextV1); err != nil {
		panic(err)
	} else {
		return URI{URL: *underlyingURL}
	}
}

type KeyType string

// JsonWebKey2020 is a VerificationMethod type.
// https://w3c-ccg.github.io/lds-jws2020/
const JsonWebKey2020 = KeyType("JsonWebKey2020")
// ED25519VerificationKey2018 is a key encoding type as specified here:
// https://w3c-ccg.github.io/lds-ed25519-2018/
const ED25519VerificationKey2018 = KeyType("Ed25519VerificationKey2018")
