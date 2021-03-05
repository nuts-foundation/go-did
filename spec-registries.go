package did

const DIDContextV1 = "https://www.w3.org/ns/did/v1"

func DIDContextV1URI() URI {
	if underlyingURL, err := ParseURI(DIDContextV1); err != nil {
		panic(err)
	} else {
		return *underlyingURL
	}
}

type KeyType string

// JsonWebKey2020 is a VerificationMethod type.
// https://w3c-ccg.github.io/lds-jws2020/
const JsonWebKey2020 = KeyType("JsonWebKey2020")

// ED25519VerificationKey2018 is the Ed25519VerificationKey2018 verification key type as specified here:
// https://w3c-ccg.github.io/lds-ed25519-2018/
const ED25519VerificationKey2018 = KeyType("Ed25519VerificationKey2018")

// ECDSASECP256K1VerificationKey2019 is the EcdsaSecp256k1VerificationKey2019 verification key type as specified here:
// https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/
const ECDSASECP256K1VerificationKey2019 = KeyType("EcdsaSecp256k1VerificationKey2019")

// RSAVerificationKey2018 is the RsaVerificationKey2018 verification key type as specified here:
// https://w3c-ccg.github.io/lds-rsa2018/
const RSAVerificationKey2018 = KeyType("RsaVerificationKey2018")

type ProofType string

// JsonWebSignature2020 is a Proof type.
// https://w3c-ccg.github.io/lds-jws2020
const JsonWebSignature2020 = ProofType("JsonWebSignature2020")


// VerifiableCredentialType is the default credential type required for every credential
const VerifiableCredentialType = "VerifiableCredential"

// VerifiableCredentialTypeV1URI returns VerifiableCredential as URI
func VerifiableCredentialTypeV1URI() URI {
	if pURI, err := ParseURI(VerifiableCredentialType); err != nil {
		panic(err)
	} else {
		return *pURI
	}
}

// DefaultContext is the context required for every credential
const VCContextV1 = "https://www.w3.org/2018/credentials/v1"

// VCContextV1URI returns 'https://www.w3.org/2018/credentials/v1' as URI
func VCContextV1URI() URI {
	if pURI, err := ParseURI(VCContextV1); err != nil {
		panic(err)
	} else {
		return *pURI
	}
}