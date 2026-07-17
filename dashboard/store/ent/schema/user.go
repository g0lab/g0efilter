package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// User is a dashboard login. Username is stored normalized (lowercased) so the
// unique index enforces case-insensitive uniqueness without a DB collation.
type User struct {
	ent.Schema
}

func (User) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "users"}}
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id"),
		field.String("username").Unique(),
		field.String("password_hash"),
		field.Int64("created_at"),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("sessions", Session.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
