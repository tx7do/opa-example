package opa

import (
	"bytes"
	"context"
	"log"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

type Opa struct {
	eq *rego.PreparedEvalQuery
	pq *rego.PreparedPartialQuery
}

func NewOpaWithString(queryString, moduleName, moduleString string) *Opa {
	ctx := context.Background()

	r := rego.New(
		rego.Query(queryString),
		rego.Module(moduleName, moduleString),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	c := &Opa{
		eq: &query,
	}

	return c
}

func NewOpaWithDataString(queryString, moduleName, moduleString, dataString string) *Opa {
	ctx := context.Background()

	store := inmem.NewFromReader(bytes.NewBufferString(dataString))

	r := rego.New(
		rego.Query(queryString),
		rego.Module(moduleName, moduleString),
		rego.Store(store),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	c := &Opa{
		eq: &query,
	}

	return c
}

func (o *Opa) CheckAllowed(ctx context.Context, input interface{}) bool {
	return o.evalQuery(ctx, input)
}

func (o *Opa) evalQuery(ctx context.Context, input interface{}) bool {
	rs, err := o.eq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
		return false
	}
	//log.Printf("eq result: %v, %#v\n", rs.Allowed(), rs)
	return rs.Allowed()
}

func (o *Opa) evalPartial(ctx context.Context, input interface{}) bool {
	_, err := o.pq.Partial(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
		return false
	}

	//log.Printf("eq result: %v, %#v\n", rs.Allowed(), rs)
	return false
}
