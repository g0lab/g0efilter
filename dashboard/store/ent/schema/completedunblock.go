package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// CompletedUnblock records an unblock operation that has been acknowledged and applied.
type CompletedUnblock struct {
	ent.Schema
}

func (CompletedUnblock) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "completed_unblocks"}}
}

func (CompletedUnblock) Fields() []ent.Field {
	return []ent.Field{
		field.String("type"),
		field.String("value"),
		field.String("target_hostname").Default(""),
		field.Int64("completed_at"),
	}
}
