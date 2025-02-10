package main

func generateJWTSerializer(def ModelDefinition, implType string) string {
	buf := "var _ " + def.Name + " = &" + implType + "{}\n"
	buf += "\n"
	buf += "type " + implType + " struct {\n"
	buf += "\ttoken jwt.Token\n"
	buf += "}\n"
	buf += "\n"
	return buf
}
