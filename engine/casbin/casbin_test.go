package casbin

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/tx7do/opa-example/engine"
	"testing"
)

var (
	allProjects = []string{
		"(unassigned)",
		"project1",
		"project2",
		"project3",
		"project4",
		"project5",
		"project6",
	}
)

func TestFilterAuthorizedPairs(t *testing.T) {
	ctx := context.Background()
	s, err := New(ctx)
	assert.Nil(t, err)

	policies := map[string]interface{}{
		"policies": []PolicyRule{
			{PType: "p", V0: "bobo", V1: "/api/*", V2: "(GET)|(POST)", V3: "*"},
			{PType: "p", V0: "bobo01", V1: "/api/users", V2: "GET", V3: "*"},
			{PType: "p", V0: "admin_role", V1: "/api/*", V2: "(GET)|(POST)", V3: "*"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "*"},
		},
		"projects": []string{},
	}

	err = s.SetPolicies(ctx, policies, nil)
	assert.Nil(t, err)

	tests := []struct {
		authorityId string
		path        string
		action      string
		equal       []engine.Pair
	}{
		{
			authorityId: "admin",
			path:        "/api/login",
			action:      "POST",
			equal:       []engine.Pair{engine.MakePair("/api/login", "POST")},
		},
		{
			authorityId: "admin",
			path:        "/api/logout",
			action:      "POST",
			equal:       []engine.Pair{engine.MakePair("/api/logout", "POST")},
		},
		{
			authorityId: "bobo",
			path:        "/api/login",
			action:      "POST",
			equal:       []engine.Pair{engine.MakePair("/api/login", "POST")},
		},
		{
			authorityId: "bobo01",
			path:        "/api/login",
			action:      "POST",
			equal:       []engine.Pair{},
		},
		{
			authorityId: "bobo01",
			path:        "/api/users",
			action:      "GET",
			equal:       []engine.Pair{engine.MakePair("/api/users", "GET")},
		},
		{
			authorityId: "bobo01",
			path:        "/api/users",
			action:      "POST",
			equal:       []engine.Pair{},
		},
	}

	for _, test := range tests {
		t.Run(test.authorityId, func(t *testing.T) {
			r, err := s.FilterAuthorizedPairs(ctx, []string{test.authorityId}, []engine.Pair{engine.MakePair(test.path, test.action)})
			assert.Nil(t, err)
			assert.EqualValues(t, test.equal, r)
			//fmt.Println(r, err)
		})
	}
}

func TestFilterAuthorizedProjects(t *testing.T) {
	ctx := context.Background()
	s, err := New(ctx)
	assert.Nil(t, err)

	policies := map[string]interface{}{
		"policies": []PolicyRule{
			{PType: "p", V0: "bobo", V1: "/api/*", V2: "(GET)|(POST)", V3: "project1"},
			{PType: "p", V0: "bobo", V1: "/api/*", V2: "(GET)|(POST)", V3: "project2"},
			{PType: "p", V0: "bobo01", V1: "/api/users", V2: "GET", V3: "*"},
			{PType: "p", V0: "admin_role", V1: "/api/*", V2: "(GET)|(POST)", V3: "*"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "*"},
		},
		"projects": allProjects,
	}

	err = s.SetPolicies(ctx, policies, nil)
	assert.Nil(t, err)

	subjects := engine.Subjects{"bobo"}
	r, err := s.FilterAuthorizedProjects(ctx, subjects)
	assert.Nil(t, err)
	fmt.Println(r)

	tests := []struct {
		subjects engine.Subjects
		equal    []string
	}{
		{
			subjects: engine.SubjectList("bobo"),
			equal:    []string{"project1", "project2"},
		},
		{
			subjects: engine.SubjectList("bobo01"),
			equal:    allProjects,
		},
		{
			subjects: engine.SubjectList("admin"),
			equal:    allProjects,
		},
		{
			subjects: engine.SubjectList("admin_role"),
			equal:    allProjects,
		},
	}

	for _, test := range tests {
		t.Run(test.subjects[0], func(t *testing.T) {
			r, err := s.FilterAuthorizedProjects(ctx, test.subjects)
			assert.Nil(t, err)
			assert.EqualValues(t, test.equal, r)
			//fmt.Println(r, err)
		})
	}
}

func TestProjectsAuthorized(t *testing.T) {
	ctx := context.Background()
	s, err := New(ctx)
	assert.Nil(t, err)

	policies := map[string]interface{}{
		"policies": []PolicyRule{
			{PType: "p", V0: "bobo", V1: "/api/*", V2: "(GET)|(POST)", V3: "project1"},
			{PType: "p", V0: "bobo", V1: "/api/*", V2: "(GET)|(POST)", V3: "project2"},
			{PType: "p", V0: "bobo01", V1: "/api/users", V2: "GET", V3: "*"},
			{PType: "p", V0: "admin_role", V1: "/api/*", V2: "(GET)|(POST)", V3: "*"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "project1"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "project2"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "project3"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "project4"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "project5"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "project6"},
			{PType: "g", V0: "admin", V1: "admin_role", V2: "(unassigned)"},
		},
		"projects": allProjects,
	}

	err = s.SetPolicies(ctx, policies, nil)
	assert.Nil(t, err)

	subjects := engine.Subjects{"bobo"}
	action := engine.Action("GET")
	resource := engine.Resource("/api/users")
	projects := engine.Projects{"project1"}
	r, err := s.ProjectsAuthorized(ctx, subjects, action, resource, projects)
	assert.Nil(t, err)
	fmt.Println(r)

	tests := []struct {
		subjects engine.Subjects
		action   engine.Action
		resource engine.Resource
		projects engine.Projects
		equal    []string
	}{
		{
			subjects: engine.SubjectList("bobo"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{"project1"},
		},
		{
			subjects: engine.SubjectList("bobo"),
			action:   engine.Action("POST"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{"project1"},
		},
		{
			subjects: engine.SubjectList("bobo"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/projects"),
			projects: engine.ProjectList("project1"),
			equal:    []string{"project1"},
		},
		{
			subjects: engine.SubjectList("bobo"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project2"),
			equal:    []string{"project2"},
		},
		{
			subjects: engine.SubjectList("bobo"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project3"),
			equal:    []string{},
		},
		{
			subjects: engine.SubjectList("bobo"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api1/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{},
		},
		{
			subjects: engine.SubjectList("bobo"),
			action:   engine.Action("DELETE"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{},
		},
		{
			subjects: engine.SubjectList("bobo999"),
			action:   engine.Action("DELETE"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{},
		},
		{
			subjects: engine.SubjectList("bobo01"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{"project1"},
		},
		{
			subjects: engine.SubjectList("bobo01"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList(allProjects...),
			equal:    allProjects,
		},
		{
			subjects: engine.SubjectList("admin"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{"project1"},
		},
		{
			subjects: engine.SubjectList("admin"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList(allProjects...),
			equal:    allProjects,
		},
		{
			subjects: engine.SubjectList("admin_role"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList("project1"),
			equal:    []string{"project1"},
		},
		{
			subjects: engine.SubjectList("admin_role"),
			action:   engine.Action("GET"),
			resource: engine.Resource("/api/users"),
			projects: engine.ProjectList(allProjects...),
			equal:    allProjects,
		},
	}

	for _, test := range tests {
		t.Run(test.subjects[0], func(t *testing.T) {
			r, err := s.ProjectsAuthorized(ctx, test.subjects, test.action, test.resource, test.projects)
			assert.Nil(t, err)
			assert.EqualValues(t, test.equal, r)
			//fmt.Println(r, err)
		})
	}
}
