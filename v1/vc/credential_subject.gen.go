package vc


import (
	"github.com/nuts-foundation/go-did/v1/ld"
	"net/url"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type CredentialSubject interface {
	// ID as defined by 
	ID() (bool, *url.URL)
}

var _ CredentialSubject = &LDCredentialSubject{}

type LDCredentialSubject struct {
	ld.Object
	context []interface{}
}

func (o LDCredentialSubject) ID() (bool, *url.URL) {
	ok, obj := o.Get("@id")
	if !ok {
		return false, ld.ToURL(nil)
	}
	return true, ld.ToURL(obj)
}

var _ CredentialSubject = &JWTCredentialSubject{}

type JWTCredentialSubject struct {
	token jwt.Token
}

