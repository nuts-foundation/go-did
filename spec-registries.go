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

// JsonWebKey2020 is a VerificationMethod type.
const JsonWebKey2020 = "JsonWebKey2020"