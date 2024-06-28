package ld

import "net/url"

type IDObject interface {
	Object
	ID() (bool, *url.URL)
}

type Object interface {
	Set(string, interface{}) error
	Get(string) (bool, interface{})
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

// IDContainer is an Object which is guaranteed to have an ID property.
type IDContainer struct {
	BaseObject
}

func (U IDContainer) ID() *url.URL {
	ok, u := U.BaseObject.ID()
	if !ok {
		return &url.URL{}
	}
	return u
}

func ToURL(obj interface{}) *url.URL {
	if obj == nil {
		return &url.URL{}
	}
	u, err := url.Parse(obj.(string))
	if err != nil {
		return &url.URL{}
	}
	return u
}
