package main

func main() {
	didDocumentDefintion := TypeDefinition{
		Name: "Document",
		Fields: []FieldDefinition{
			{
				Name:     "Context",
				JSONName: "@context",
				GoType:   "[]interface",
			},
			{
				Name:     "ID",
				JSONName: "id",
				GoType:   "DID",
			},
			{
				Name:     "AlsoKnownAs",
				JSONName: "alsoKnownAs",
				GoType:   "[]ssi.URI",
			},
			{
				Name:     "VerificationMethod",
				JSONName: "verificationMethod",
				GoType:   "VerificationMethods",
			},
			{
				Name:     "Authentication",
				JSONName: "authentication",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "AssertionMethod",
				JSONName: "assertionMethod",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "KeyAgreement",
				JSONName: "keyAgreement",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "CapabilityInvocation",
				JSONName: "capabilityInvocation",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "CapabilityDelegation",
				JSONName: "capabilityDelegation",
				GoType:   "VerificationRelationships",
			},
			{
				Name:     "Service",
				JSONName: "service",
				GoType:   "[]Service",
			},
		},
	}
}

type TypeDefinition struct {
	Name   string
	Fields []FieldDefinition
}

type FieldDefinition struct {
	Name     string
	JSONName string
	GoType   string
}

func generate(typeDef TypeDefinition) string {
	buf := ""
	buf += "package did\n\n"
	buf += "type " + typeDef.Name + " struct {\n"
	buf += "\t properties map[string]interface{}"
	buf += "}\n"
	buf += "\n"
	buf += "func (d " + typeDef.Name + ") Get(key string) interface{} {\n"
	buf += "\t return d.properties[key]\n"
	buf += "}\n"
}
