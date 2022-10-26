package opa

import (
	"bytes"
	"context"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"log"
)

type Opa struct {
	opa *rego.PreparedEvalQuery
	pr  *rego.PartialResult
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
		opa: &query,
	}

	return c
}

func NewOpaWithStringPartial(queryString, moduleName, moduleString, partialString string) *Opa {
	ctx := context.Background()

	store := inmem.NewFromReader(bytes.NewBufferString(partialString))

	r := rego.New(
		rego.Query(queryString),
		rego.Module(moduleName, moduleString),
		rego.Store(store),
	)

	pr, err := r.PartialResult(ctx)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	c := &Opa{
		pr: &pr,
	}

	return c
}

func (o *Opa) Test(ctx context.Context, input interface{}) bool {
	if o.opa != nil {
		return o.evalQuery(ctx, input)
	} else if o.pr != nil {
		return o.evalPartial(ctx, input)
	}
	return false
}

func (o *Opa) evalQuery(ctx context.Context, input interface{}) bool {
	rs, err := o.opa.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
		return false
	}
	//log.Printf("opa result: %v, %#v\n", rs.Allowed(), rs)
	return rs.Allowed()
}

func (o *Opa) evalPartial(ctx context.Context, input interface{}) bool {
	r := o.pr.Rego(
		rego.Input(input),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		log.Fatal(err)
		return false
	}

	//log.Printf("opa result: %v, %#v\n", rs.Allowed(), rs)
	return rs.Allowed()
}
