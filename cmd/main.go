package main

import (
	"os"
)

func main() {
	err := os.WriteFile("../v1/vc/model.gen.go", []byte(generate("vc", verifiableCredential())), 0644)
	if err != nil {
		panic(err)
	}
}

type TypeDefinition struct {
	Name   string
	Fields []FieldDefinition
}

type FieldDefinition struct {
	Name     string
	JSONName string
	IRI      string
	Required bool
	DocLink  string
	GoType   string
}

func generate(pkg string, def TypeDefinition) string {
	implType := "LD" + def.Name
	buf := ""
	buf += "package " + pkg + "\n\n"
	buf += "\n"
	buf += `import (
	"github.com/nuts-foundation/go-did/v1/ld"
	"time"
)`
	buf += "\n\n"
	// Interface type
	buf += "type " + def.Name + " interface {\n"
	buf += "\tld.Object\n"
	buf += "\tContext() []interface{}\n"
	for _, field := range def.Fields {
		buf += "\t// " + field.Name + " as defined by " + field.DocLink + "\n"
		if field.Required {
			buf += "\t" + field.Name + "() " + field.GoType + "\n"
		} else {
			buf += "\t" + field.Name + "() (bool, " + field.GoType + ")\n"
		}
	}
	buf += "}\n"
	buf += "\n"
	// Implementation type
	buf += "var _ " + def.Name + " = &" + implType + "{}\n"
	buf += "\n"
	buf += "type " + implType + " struct {\n"
	buf += "\tld.Object\n"
	buf += "\tcontext []interface{}\n"
	buf += "}\n"
	buf += "\n"
	// Fixed Context field
	buf += "func (o " + implType + ") Context() []interface{} {\n"
	buf += "\treturn o.context\n"
	buf += "}\n\n"
	// Type-specific fields
	for _, field := range def.Fields {
		returnType := field.GoType
		if !field.Required {
			returnType = "(bool, " + field.GoType + ")"
		}
		buf += "func (o " + implType + ") " + field.Name + "() " + returnType + " {\n"
		if field.Required {
			buf += "\tok, obj := o.Get(\"" + field.IRI + "\")\n"
			buf += "\tif !ok {\n"
			buf += "\t\treturn " + nilValue(field.GoType) + "\n"
			buf += "\t}\n"
			buf += "\treturn " + converterFunc(field.GoType) + "(obj)\n"
		} else {
			buf += "\tok, obj := o.Get(\"" + field.IRI + "\")\n"
			buf += "\tif !ok {\n"
			buf += "\t\treturn false, " + converterFunc(field.GoType) + "(nil)\n"
			buf += "\t}\n"
			buf += "\treturn true, " + converterFunc(field.GoType) + "(obj)\n"
		}
		buf += "}\n\n"
	}
	return buf
}

func nilValue(goType string) string {
	switch goType {
	case "ld.IDObject":
		return "ld.IDObject{}"
	case "time.Time":
		return "time.Time{}"
	default:
		return "nil"
	}
}

func converterFunc(goType string) string {
	switch goType {
	case "ld.Object":
		return "ld.ToObject"
	case "[]ld.Object":
		return "ld.ToObjects"
	case "ld.IDObject":
		return "ld.NewIDObject"
	case "time.Time":
		return "ld.ToTime"
	case "[]string":
		return "ld.ToStrings"
	case "[]interface{}":
		return "ld.ToInterfaces"
	default:
		return "MISSING_CONVERTER"
	}
}
