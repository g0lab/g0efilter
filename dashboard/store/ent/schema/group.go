package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Group is a named set of instances sharing a policy and settings (fleet).
type Group struct {
	ent.Schema
}

func (Group) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "fleet_groups"}}
}

func (Group) Fields() []ent.Field {
	return []ent.Field{
		field.String("id"),
		field.String("name").Unique(),
		field.String("policy").Default(""),
		field.String("filter_mode").Default(""),
		field.Int64("updated_at"),
	}
}

func (Group) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("instances", Instance.Type),
	}
}
