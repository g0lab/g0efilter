package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Session is an authenticated browser session. Only the SHA-256 of the token
// is persisted, so a database read cannot hijack live sessions.
type Session struct {
	ent.Schema
}

func (Session) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "sessions"}}
}

func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.Bytes("token_hash").Unique(),
		field.String("user_id"),
		field.Int64("created_at"),
		field.Int64("expires_at"),
	}
}

func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("sessions").
			Field("user_id").
			Unique().
			Required(),
	}
}

func (Session) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
	}
}
