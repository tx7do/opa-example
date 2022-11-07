package engine

import (
	"context"
)

type Engine interface {
	Authorizer
	Writer
}

type Authorizer interface {
	ProjectsAuthorized(ctx context.Context, subjects Subjects, action Action, resource Resource, projects Projects) ([]string, error)

	FilterAuthorizedPairs(ctx context.Context, subjects Subjects, pairs []Pair) ([]Pair, error)

	FilterAuthorizedProjects(ctx context.Context, subjects Subjects) ([]string, error)
}

type Writer interface {
	SetPolicies(ctx context.Context, policyMap map[string]interface{}, roleMap map[string]interface{}) error
}

type Subjects []string

func SubjectList(subs ...string) Subjects {
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

func MakePair(res, act string) Pair {
	return Pair{Resource(res), Action(act)}
}
