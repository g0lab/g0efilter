package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Instance is a g0efilter node known to the fleet control plane.
type Instance struct {
	ent.Schema
}

func (Instance) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "fleet_instances"}}
}

func (Instance) Fields() []ent.Field {
	return []ent.Field{
		field.String("id"),
		field.String("hostname").Unique(),
		field.String("group_id").Optional(), // NULL = unmanaged
		field.String("policy_override").Optional().Nillable(),
		field.String("filter_mode").Default(""),
		field.String("reported_version").Default(""),
		field.String("reported_hash").Default(""),
		field.Int64("last_seen_at"),
		field.Int64("created_at"),
	}
}

func (Instance) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("group", Group.Type).
			Ref("instances").
			Field("group_id").
			Unique().
			Annotations(entsql.OnDelete(entsql.SetNull)),
	}
}

func (Instance) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id"),
	}
}
