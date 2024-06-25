package ld

import (
	"time"
)

func ToStrings(value interface{}) []string {
	var results []string
	values, ok := value.([]interface{})
	if ok {
		for _, raw := range values {
			val, ok := raw.(string)
			if ok {
				results = append(results, val)
			}
		}
	}
	return results
}

func ToTime(obj interface{}) time.Time {
	value, ok := getValue(obj).(string)
	if !ok {
		return time.Time{}
	}
	result, _ := time.Parse(time.RFC3339, value)
	return result
}

func NewIDObject(obj interface{}) IDObject {
	return IDObject{
		map[string]interface{}{
			"@id": obj,
		},
	}
}

func getValue(input interface{}) interface{} {
	asSlice, ok := input.([]interface{})
	if !ok || len(asSlice) == 0 {
		return nil
	}
	asMap, ok := asSlice[0].(map[string]interface{})
	if !ok {
		return nil
	}
	return asMap["@value"]
}

func ToInterfaces(input interface{}) []interface{} {
	asSlice, ok := input.([]interface{})
	if !ok || len(asSlice) == 0 {
		return nil
	}
	return asSlice
}

func ToObject(input interface{}) Object {
	asMap, ok := input.(map[string]interface{})
	if !ok {
		return BaseObject{}
	}
	return BaseObject(asMap)
}

func ToObjects(obj interface{}) []Object {
	asSlice, ok := obj.([]interface{})
	if !ok {
		return nil
	}
	var results []Object
	for _, raw := range asSlice {
		results = append(results, ToObject(raw))
	}
	return results
}
