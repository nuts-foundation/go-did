package ld

import "net/url"

type Object interface {
	Set(string, interface{}) error
	Get(string) (bool, interface{})
	ID() (bool, *url.URL)
}

var _ Object = &BaseObject{}

type BaseObject map[string]interface{}

func (o BaseObject) ID() (bool, *url.URL) {
	ok, id := o.Get("@id")
	if !ok {
		return false, &url.URL{}
	}
	result, err := url.Parse(id.(string))
	if err != nil {
		return false, &url.URL{}
	}
	return true, result
}

func (o BaseObject) Set(s string, i interface{}) error {
	//TODO implement me
	panic("implement me")
}

func (o BaseObject) Get(s string) (bool, interface{}) {
	v, ok := o[s]
	return ok, v
}

// IDObject is an Object which is guaranteed to have an ID property.
type IDObject struct {
	BaseObject
}

func (U IDObject) ID() *url.URL {
	ok, u := U.BaseObject.ID()
	if !ok {
		return &url.URL{}
	}
	return u
}
