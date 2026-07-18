package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UnblockRequest is a pending request to remove a block rule.
type UnblockRequest struct {
	ent.Schema
}

func (UnblockRequest) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "unblock_requests"}}
}

func (UnblockRequest) Fields() []ent.Field {
	return []ent.Field{
		field.String("id"),
		field.String("type"), // "domain" or "ip"
		field.String("value"),
		field.String("target_hostname").Default(""),
		field.Int64("created_at"),
	}
}

func (UnblockRequest) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("type", "value", "target_hostname").Unique(),
	}
}
