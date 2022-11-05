package engine

import (
	"context"
)

type Engine interface {
	Authorizer
	Writer
}

type Authorizer interface {
	ProjectsAuthorized(context.Context, Subjects, Action, Resource, Projects) ([]string, error)

	FilterAuthorizedPairs(context.Context, Subjects, []Pair) ([]Pair, error)

	FilterAuthorizedProjects(context.Context, Subjects) ([]string, error)
}

type Writer interface {
	SetPolicies(context.Context, map[string]interface{}, map[string]interface{}) error
}

type Subjects []string

func Subject(subs ...string) Subjects {
	return subs
}

type Projects []string

func ProjectList(projects ...string) []string {
	return projects
}

type Action string

type Resource string

type Project string

type Pair struct {
	Resource Resource `json:"resource"`
	Action   Action   `json:"action"`
}
