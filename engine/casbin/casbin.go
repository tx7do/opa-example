package casbin

import (
	"context"
	"go.uber.org/zap"

	stdCasbin "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

	"github.com/tx7do/opa-example/engine"
)

const (
	wildcardItem              = "*"
	authorizedProjectsMatcher = "g(r.sub, p.sub, p.dom) && (keyMatch(r.dom, p.dom) || p.dom == '*')"
)

type State struct {
	model    model.Model
	policy   *Adapter
	enforcer *stdCasbin.SyncedEnforcer

	log *zap.Logger
}

func New(_ context.Context, opts ...OptFunc) (*State, error) {
	s := State{
		policy: newAdapter(),
	}

	for _, opt := range opts {
		opt(&s)
	}

	var err error

	if s.model == nil {
		s.model, err = model.NewModelFromString(DefaultRestfullWithRoleModel)
		if err != nil {
			return nil, err
		}
	}

	s.enforcer, err = stdCasbin.NewSyncedEnforcer(s.model, s.policy)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (s *State) ProjectsAuthorized(_ context.Context,
	subjects engine.Subjects,
	action engine.Action,
	resource engine.Resource,
	projects engine.Projects) ([]string, error) {

	result := make([]string, 0, len(projects))

	var err error
	var allowed bool
	for _, project := range projects {
		for _, subject := range subjects {
			if allowed, err = s.enforcer.Enforce(subject, string(resource), string(action), project); err != nil {
				//fmt.Println(allowed, err)
				return nil, err
			} else if allowed {
				result = append(result, project)
			}
		}
	}

	return result, nil
}

func (s *State) FilterAuthorizedProjects(_ context.Context, subjects engine.Subjects) ([]string, error) {
	projects := s.policy.GetProjects()
	result := make([]string, 0, len(projects))

	var err error
	var allowed bool
	for _, project := range projects {
		for _, subject := range subjects {
			if allowed, err = s.enforcer.EnforceWithMatcher(authorizedProjectsMatcher, subject, wildcardItem, wildcardItem, project); err != nil {
				//fmt.Println(allowed, err)
				return nil, err
			} else if allowed {
				result = append(result, project)
			}
		}
	}
	return result, nil
}

func (s *State) FilterAuthorizedPairs(_ context.Context, subjects engine.Subjects, pairs []engine.Pair) ([]engine.Pair, error) {
	result := make([]engine.Pair, 0, len(pairs))

	var err error
	var allowed bool
	for _, p := range pairs {
		for _, subject := range subjects {
			if allowed, err = s.enforcer.Enforce(subject, string(p.Resource), string(p.Action), wildcardItem); err != nil {
				//fmt.Println(allowed, err)
				return nil, err
			} else if allowed {
				result = append(result, p)
			}
		}
	}
	return result, nil
}

func (s *State) SetPolicies(_ context.Context, policyMap map[string]interface{}, _ map[string]interface{}) error {
	s.policy.SetPolicies(policyMap)
	err := s.enforcer.LoadPolicy()
	//fmt.Println(err, s.enforcer.GetAllSubjects(), s.enforcer.GetAllRoles())
	return err
}
