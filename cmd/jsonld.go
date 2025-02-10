package main

func generateLDSerializer(def ModelDefinition, implType string) string {
	buf := "var _ " + def.Name + " = &" + implType + "{}\n"
	buf += "\n"
	buf += "type " + implType + " struct {\n"
	buf += "\tld.Object\n"
	buf += "\tcontext []interface{}\n"
	buf += "}\n"
	buf += "\n"
	// Type-specific fields
	for _, field := range def.Fields {
		returnType := field.GoType
		if !field.Required {
			returnType = "(bool, " + field.GoType + ")"
		}
		buf += "func (o " + implType + ") " + field.Name + "() " + returnType + " {\n"
		if field.Name == "Context" {
			// Fixed Context field
			buf += "\treturn o.context\n"
		} else {
			if field.Required {
				buf += "\tok, obj := o.Get(\"" + field.IRI + "\")\n"
				buf += "\tif !ok {\n"
				buf += "\t\treturn " + ldNilValue(field.GoType) + "\n"
				buf += "\t}\n"
				buf += "\treturn " + converterFunc(field.GoType) + "(obj)\n"
			} else {
				buf += "\tok, obj := o.Get(\"" + field.IRI + "\")\n"
				buf += "\tif !ok {\n"
				buf += "\t\treturn false, " + converterFunc(field.GoType) + "(nil)\n"
				buf += "\t}\n"
				buf += "\treturn true, " + converterFunc(field.GoType) + "(obj)\n"
			}
		}
		buf += "}\n\n"
	}
	return buf
}

func ldNilValue(goType string) string {
	switch goType {
	case "ld.IDObject":
		return "ld.IDObject{}"
	case "time.Time":
		return "time.Time{}"
	default:
		return "nil"
	}
}
