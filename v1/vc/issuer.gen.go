package vc


import (
	"github.com/nuts-foundation/go-did/v1/ld"
	"net/url"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Issuer interface {
	// ID as defined by 
	ID() *url.URL
}

var _ Issuer = &LDIssuer{}

type LDIssuer struct {
	ld.Object
	context []interface{}
}

func (o LDIssuer) ID() *url.URL {
	ok, obj := o.Get("@id")
	if !ok {
		return nil
	}
	return ld.ToURL(obj)
}

var _ Issuer = &JWTIssuer{}

type JWTIssuer struct {
	token jwt.Token
}

