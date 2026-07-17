package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// APIKey is a machine credential. Only the SHA-256 hash of the key is stored.
type APIKey struct {
	ent.Schema
}

func (APIKey) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "api_keys"}}
}

func (APIKey) Fields() []ent.Field {
	return []ent.Field{
		field.String("id"),
		field.String("label"),
		field.Bytes("key_hash").Unique(),
		field.String("key_prefix"),
		field.Int64("created_at"),
		field.Int64("last_used_at").Optional().Nillable(),
		field.Int64("revoked_at").Optional().Nillable(),
	}
}
