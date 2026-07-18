package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Setting is a key/value row for server-managed secrets and config, such as the
// API-key HMAC pepper generated on first boot.
type Setting struct {
	ent.Schema
}

func (Setting) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "settings"}}
}

func (Setting) Fields() []ent.Field {
	return []ent.Field{
		field.String("key").Unique(),
		field.Bytes("value"),
	}
}
