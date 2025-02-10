package vc

import (
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/url"
	"time"
)

var _ VerifiableCredential = &JWTVerifiableCredential{}

type JWTVerifiableCredential struct {
	token jwt.Token
}

func (j JWTVerifiableCredential) Context() []interface{} {
	//TODO implement me
	panic("implement me")
}

func (j JWTVerifiableCredential) ID() (bool, *url.URL) {
	id := j.token.JwtID()
	if id == "" {
		return false, nil
	}
	result, _ := url.Parse(id)
	return result != nil, result
}

func (j JWTVerifiableCredential) Type() []string {
	vc, ok := j.token.Get("vc")
}

func (j JWTVerifiableCredential) Issuer() Issuer {
	//TODO implement me
	panic("implement me")
}

func (j JWTVerifiableCredential) IssuanceDate() time.Time {
	//TODO implement me
	panic("implement me")
}

func (j JWTVerifiableCredential) ExpirationDate() (bool, time.Time) {
	//TODO implement me
	panic("implement me")
}

func (j JWTVerifiableCredential) CredentialSubject() []CredentialSubject {
	//TODO implement me
	panic("implement me")
}
