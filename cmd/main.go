package main

import (
	"os"
	"strings"
)

func main() {
	targets := []struct {
		file string
		pkg  string
		def  ModelDefinition
	}{
		{
			file: "../v1/vc/verifiable_credential.gen.go",
			pkg:  "vc",
			def:  verifiableCredential(),
		},
		{
			file: "../v1/vc/issuer.gen.go",
			pkg:  "vc",
			def:  issuer(),
		},
		{
			file: "../v1/vc/credential_subject.gen.go",
			pkg:  "vc",
			def:  credentialSubject(),
		},
		{
			file: "../v1/did/model.gen.go",
			pkg:  "did",
			def:  didDocument(),
		},
	}
	for _, target := range targets {
		err := os.WriteFile(target.file, []byte(generate(target.pkg, target.def)), 0644)
		if err != nil {
			panic(err)
		}
	}
}

type ModelDefinition struct {
	Name                    string
	Fields                  []FieldDefinition
	Imports                 []string
	SupportLDSerialization  bool
	SupportJWTSerialization bool
}

type FieldDefinition struct {
	Name     string
	JSONName string
	IRI      string
	JWTClaim string
	Required bool
	DocLink  string
	GoType   string
}

func generate(pkg string, def ModelDefinition) string {
	buf := ""
	buf += "package " + pkg + "\n\n"
	buf += "\n"
	// Imports
	buf += "import (\n"
	for _, imp := range def.Imports {
		buf += "\t" + imp + "\n"
	}
	if def.SupportJWTSerialization {
		buf += "\t\"github.com/lestrrat-go/jwx/v2/jwt\"\n"
	}
	buf += ")\n"
	buf += "\n"
	// Interface type
	buf += "type " + def.Name + " interface {\n"
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
	if def.SupportLDSerialization {
		buf += generateLDSerializer(def, "LD"+def.Name)
	}
	if def.SupportJWTSerialization {
		buf += generateJWTSerializer(def, "JWT"+def.Name)
	}
	return buf
}

func converterFunc(goType string) string {
	isSlice := goType[0] == '['
	parts := strings.Split(goType, ".")
	name := parts[len(parts)-1]
	// Remove non-alphanumeric characters
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return -1
	}, name)

	var pkg string
	if len(parts) > 1 || strings.ToLower(name) == name {
		pkg = "ld"
	}

	if isSlice {
		name += "s"
	}
	// First character to upper
	name = "To" + strings.ToUpper(name[:1]) + name[1:]
	if pkg != "" {
		name = pkg + "." + name
	}
	return name
}
