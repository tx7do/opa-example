package opa

import (
	"bytes"
	"context"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"log"
)

type Opa struct {
	eq    *rego.PreparedEvalQuery
	pq    *rego.PreparedPartialQuery
	store storage.Store
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

	c := &Opa{
		store: inmem.NewFromReader(bytes.NewBufferString(dataString)),
	}

	r := rego.New(
		rego.Query(queryString),
		rego.Module(moduleName, moduleString),
		rego.Store(c.store),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	c.eq = &query

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

func (o *Opa) updateData(ctx context.Context, packagePath string, data interface{}) bool {
	params := storage.WriteParams

	txn, err := o.store.NewTransaction(ctx, params)
	if err != nil {
		log.Fatal(err)
		return false
	}

	p, ok := storage.ParsePath(packagePath)
	if !ok {
		return false
	}

	if err := o.store.Write(ctx, txn, storage.ReplaceOp, p, data); err != nil {
		log.Fatal(err)
		return false
	}

	if err := o.store.Commit(ctx, txn); err != nil {
		log.Fatal(err)
		return false
	}

	return true
}
