package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// LogEvent is a persisted log event (stored when DB_PATH is set). data holds the
// full LogEntry as JSON; search is a lowercased haystack for substring filtering.
// Named LogEvent (not Log) to avoid Ent's predeclared "Log" identifier; the
// table is still "logs".
type LogEvent struct {
	ent.Schema
}

func (LogEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "logs"}}
}

func (LogEvent) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("ts"), // unix nanoseconds, for stable ordering
		field.Text("data"),
		field.Text("search"),
	}
}

func (LogEvent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ts"),
	}
}
