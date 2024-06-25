package vc

import (
	"github.com/nuts-foundation/go-did/v1/ld"
	"time"
)

type VerifiableCredential interface {
	ld.Object
	Context() []interface{}
	// Type as defined by https://www.w3.org/TR/vc-data-model/#types
	Type() []string
	// Issuer as defined by https://www.w3.org/TR/vc-data-model/#issuer
	Issuer() ld.IDObject
	// IssuanceDate as defined by https://www.w3.org/TR/vc-data-model/#issuance
	IssuanceDate() time.Time
	// ExpirationDate as defined by https://www.w3.org/TR/vc-data-model/#expiration
	ExpirationDate() (bool, time.Time)
	// CredentialSubject as defined by https://www.w3.org/TR/vc-data-model/#credential-subject
	CredentialSubject() []ld.Object
}

var _ VerifiableCredential = &LDVerifiableCredential{}

type LDVerifiableCredential struct {
	ld.Object
	context []interface{}
}

func (o LDVerifiableCredential) Context() []interface{} {
	return o.context
}

func (o LDVerifiableCredential) Type() []string {
	ok, obj := o.Get("@type")
	if !ok {
		return nil
	}
	return ld.ToStrings(obj)
}

func (o LDVerifiableCredential) Issuer() ld.IDObject {
	ok, obj := o.Get("https://www.w3.org/2018/credentials#issuer")
	if !ok {
		return ld.IDObject{}
	}
	return ld.NewIDObject(obj)
}

func (o LDVerifiableCredential) IssuanceDate() time.Time {
	ok, obj := o.Get("https://www.w3.org/2018/credentials#issuanceDate")
	if !ok {
		return time.Time{}
	}
	return ld.ToTime(obj)
}

func (o LDVerifiableCredential) ExpirationDate() (bool, time.Time) {
	ok, obj := o.Get("https://www.w3.org/2018/credentials#expirationDate")
	if !ok {
		return false, ld.ToTime(nil)
	}
	return true, ld.ToTime(obj)
}

func (o LDVerifiableCredential) CredentialSubject() []ld.Object {
	ok, obj := o.Get("https://www.w3.org/2018/credentials#credentialSubject")
	if !ok {
		return nil
	}
	return ld.ToObjects(obj)
}
