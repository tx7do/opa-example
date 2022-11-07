package opa

import (
	"github.com/open-policy-agent/opa/ast"
	"go.uber.org/zap"
)

// OptFunc is the type of functional options to be passed to New()
type OptFunc func(*State)

// WithModules allows for injecting an OPA policy via opa.New() for engine
// initialization.
func WithModules(mods map[string]*ast.Module) OptFunc {
	return func(s *State) {
		s.modules = mods
	}
}

func WithLogger(l *zap.Logger) OptFunc {
	return func(s *State) {
		s.log = l
	}
}
