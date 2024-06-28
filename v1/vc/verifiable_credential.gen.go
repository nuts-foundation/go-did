package vc

import (
	"github.com/nuts-foundation/go-did/v1/ld"
	"net/url"
	"time"
)

type VerifiableCredential interface {
	// Context as defined by https://www.w3.org/TR/vc-data-model/#context-urls
	Context() []interface{}
	// ID as defined by 
	ID() (bool, *url.URL)
	// Type as defined by https://www.w3.org/TR/vc-data-model/#types
	Type() []string
	// Issuer as defined by https://www.w3.org/TR/vc-data-model/#issuer
	Issuer() Issuer
	// IssuanceDate as defined by https://www.w3.org/TR/vc-data-model/#issuance
	IssuanceDate() time.Time
	// ExpirationDate as defined by https://www.w3.org/TR/vc-data-model/#expiration
	ExpirationDate() (bool, time.Time)
	// CredentialSubject as defined by https://www.w3.org/TR/vc-data-model/#credential-subject
	CredentialSubject() []CredentialSubject
}

var _ VerifiableCredential = &LDVerifiableCredential{}

type LDVerifiableCredential struct {
	ld.Object
	context []interface{}
}

func (o LDVerifiableCredential) Context() []interface{} {
	return o.context
}

func (o LDVerifiableCredential) ID() (bool, *url.URL) {
	ok, obj := o.Get("@id")
	if !ok {
		return false, ld.ToURL(nil)
	}
	return true, ld.ToURL(obj)
}

func (o LDVerifiableCredential) Type() []string {
	ok, obj := o.Get("@type")
	if !ok {
		return nil
	}
	return ld.ToStrings(obj)
}

func (o LDVerifiableCredential) Issuer() Issuer {
	ok, obj := o.Get("https://www.w3.org/2018/credentials#issuer")
	if !ok {
		return nil
	}
	return ToIssuer(obj)
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

func (o LDVerifiableCredential) CredentialSubject() []CredentialSubject {
	ok, obj := o.Get("https://www.w3.org/2018/credentials#credentialSubject")
	if !ok {
		return nil
	}
	return ToCredentialSubjects(obj)
}
