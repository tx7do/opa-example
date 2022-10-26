package opa

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	//go:embed module/authz.rego
	authzConf string

	//go:embed module/rbac.rego
	rbacConf string
)

func Test_Authz_Embed(t *testing.T) {
	ctx := context.Background()
	o := NewOpaWithString("data.authz.allow", "authz.repo", authzConf)

	{
		input := map[string]interface{}{
			"method": "GET",
			"path":   "/api",
			"subject": map[string]interface{}{
				"user":  "user",
				"group": "groups",
			},
		}
		assert.True(t, o.Test(ctx, input))
	}
	{
		input := map[string]interface{}{
			"method": "PUT",
			"path":   "/api",
			"subject": map[string]interface{}{
				"user":  "user",
				"group": "groups",
			},
		}
		assert.False(t, o.Test(ctx, input))
	}
	{
		input := map[string]interface{}{
			"method": "GET",
			"path":   "/pul",
			"subject": map[string]interface{}{
				"user":  "user",
				"group": "groups",
			},
		}
		assert.True(t, o.Test(ctx, input))
	}
	{
		input := map[string]interface{}{
			"method": "GET",
			"path":   "/api",
			"subject": map[string]interface{}{
				"user":  "",
				"group": "",
			},
		}
		assert.False(t, o.Test(ctx, input))
	}
}

func Test_Rego_Eval_simple(t *testing.T) {

	ctx := context.Background()

	// Create very simple query that binds a single variable.
	r := rego.New(rego.Query("x = 1"))

	// Run evaluation.
	rs, err := r.Eval(ctx)

	// Inspect results.
	fmt.Println("len:", len(rs))
	fmt.Println("bindings:", rs[0].Bindings)
	fmt.Println("err:", err)

	// Output:
	//
	// len: 1
	// bindings: map[x:1]
	// err: <nil>
}

func Test_Rego_Eval_singleDocument(t *testing.T) {

	ctx := context.Background()

	// Create query that produces a single document.
	r := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
p = ["hello", "world"] { true }`,
		))

	// Run evaluation.
	rs, err := r.Eval(ctx)

	// Inspect result.
	fmt.Println("value:", rs[0].Expressions[0].Value)
	fmt.Println("err:", err)

	// Output:
	//
	// value: [hello world]
	// err: <nil>
}

func Test_Rego_Eval_allowed(t *testing.T) {

	ctx := context.Background()

	// Create query that returns a single boolean value.
	r := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("example.rego",
			`package authz
default allow = false
allow {
	input.open == "sesame"
}`,
		),
		rego.Input(map[string]interface{}{"open": "sesame"}),
	)

	// Run evaluation.
	rs, err := r.Eval(ctx)
	if err != nil {
		panic(err)
	}

	// Inspect result.
	fmt.Println("allowed:", rs.Allowed())

	// Output:
	//
	//	allowed: true
}

func Test_Rego_Eval_storage(t *testing.T) {

	ctx := context.Background()

	data := `{
        "example": {
            "users": [
                {
                    "name": "alice",
                    "likes": ["dogs", "clouds"]
                },
                {
                    "name": "bob",
                    "likes": ["pizza", "cats"]
                }
            ]
        }
    }`

	var json map[string]interface{}

	err := util.UnmarshalJSON([]byte(data), &json)
	if err != nil {
		// Handle error.
	}

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(json)

	// Create new query that returns the value
	r := rego.New(
		rego.Query("data.example.users[0].likes"),
		rego.Store(store))

	// Run evaluation.
	rs, err := r.Eval(ctx)
	if err != nil {
		// Handle error.
	}

	// Inspect the result.
	fmt.Println("value:", rs[0].Expressions[0].Value)

	// Output:
	//
	// value: [dogs clouds]
}

func Test_Rego_PartialResult(t *testing.T) {

	ctx := context.Background()

	// Define a role-based access control (RBAC) policy that decides whether to
	// allow or deny requests. Requests are allowed if the user is bound to a
	// role that grants permission to perform the operation on the resource.
	module := `
		package example
		import data.bindings
		import data.roles
		default allow = false
		allow {
			user_has_role[role_name]
			role_has_permission[role_name]
		}
		user_has_role[role_name] {
			b = bindings[_]
			b.role = role_name
			b.user = input.subject.user
		}
		role_has_permission[role_name] {
			r = roles[_]
			r.name = role_name
			match_with_wildcard(r.operations, input.operation)
			match_with_wildcard(r.resources, input.resource)
		}
		match_with_wildcard(allowed, value) {
			allowed[_] = "*"
		}
		match_with_wildcard(allowed, value) {
			allowed[_] = value
		}
	`

	// Define dummy roles and role bindings for the example. In real-world
	// scenarios, this data would be pushed or pulled into the service
	// embedding OPA either from an external API or configuration file.
	store := inmem.NewFromReader(bytes.NewBufferString(`{
		"roles": [
			{
				"resources": ["documentA", "documentB"],
				"operations": ["read"],
				"name": "analyst"
			},
			{
				"resources": ["*"],
				"operations": ["*"],
				"name": "admin"
			}
		],
		"bindings": [
			{
				"user": "bob",
				"role": "admin"
			},
			{
				"user": "alice",
				"role": "analyst"
			}
		]
	}`))

	// Prepare and run partial evaluation on the query. The result of partial
	// evaluation can be cached for performance. When the data or policy
	// change, partial evaluation should be re-run.
	r := rego.New(
		rego.Query("data.example.allow"),
		rego.Module("example.rego", module),
		rego.Store(store),
	)

	pr, err := r.PartialResult(ctx)
	if err != nil {
		// Handle error.
	}

	// Define example inputs (representing requests) that will be used to test
	// the policy.
	examples := []map[string]interface{}{
		{
			"resource":  "documentA",
			"operation": "write",
			"subject": map[string]interface{}{
				"user": "bob",
			},
		},
		{
			"resource":  "documentB",
			"operation": "write",
			"subject": map[string]interface{}{
				"user": "alice",
			},
		},
		{
			"resource":  "documentB",
			"operation": "read",
			"subject": map[string]interface{}{
				"user": "alice",
			},
		},
	}

	for i := range examples {

		// Prepare and run normal evaluation from the result of partial
		// evaluation.
		r := pr.Rego(
			rego.Input(examples[i]),
		)

		rs, err := r.Eval(ctx)

		if err != nil || len(rs) != 1 || len(rs[0].Expressions) != 1 {
			// Handle erorr.
		} else {
			fmt.Printf("input %d allowed: %v\n", i+1, rs[0].Expressions[0].Value)
		}
	}

	// Output:
	//
	// input 1 allowed: true
	// input 2 allowed: false
	// input 3 allowed: true
}

func Test_RBAC_String(t *testing.T) {
	module := `
		package example
		import data.bindings
		import data.roles
		default allow = false
		allow {
			user_has_role[role_name]
			role_has_permission[role_name]
		}
		user_has_role[role_name] {
			b = bindings[_]
			b.role = role_name
			b.user = input.subject.user
		}
		role_has_permission[role_name] {
			r = roles[_]
			r.name = role_name
			match_with_wildcard(r.operations, input.operation)
			match_with_wildcard(r.resources, input.resource)
		}
		match_with_wildcard(allowed, value) {
			allowed[_] = "*"
		}
		match_with_wildcard(allowed, value) {
			allowed[_] = value
		}
	`

	data := `{
		"roles": [
			{
				"resources": ["documentA", "documentB"],
				"operations": ["read"],
				"name": "analyst"
			},
			{
				"resources": ["*"],
				"operations": ["*"],
				"name": "admin"
			}
		],
		"bindings": [
			{
				"user": "bob",
				"role": "admin"
			},
			{
				"user": "alice",
				"role": "analyst"
			}
		]
	}`

	ctx := context.Background()
	o := NewOpaWithStringPartial("data.example.allow", "rbac.repo", module, data)

	examples := []map[string]interface{}{
		{
			"resource":  "documentA",
			"operation": "write",
			"subject": map[string]interface{}{
				"user": "bob",
			},
		},
		{
			"resource":  "documentB",
			"operation": "write",
			"subject": map[string]interface{}{
				"user": "alice",
			},
		},
		{
			"resource":  "documentB",
			"operation": "read",
			"subject": map[string]interface{}{
				"user": "alice",
			},
		},
	}

	for i := range examples {
		allowed := o.Test(ctx, examples[i])
		{
			fmt.Printf("input %d allowed: %v\n", i+1, allowed)
		}
	}

	// Output:
	//
	// input 1 allowed: true
	// input 2 allowed: false
	// input 3 allowed: true
}
