package casbin

import (
	"errors"
	"github.com/casbin/casbin/v2/model"
)

type Adapter struct {
	policies map[string]interface{}
}

func newAdapter() *Adapter {
	return &Adapter{
		policies: map[string]interface{}{},
	}
}

func (sa *Adapter) LoadPolicy(model model.Model) error {
	policiesInterface, ok := sa.policies["policies"]
	if ok {
		policies := policiesInterface.([]PolicyRule)
		for _, line := range policies {
			if err := line.LoadPolicyLine(model); err != nil {
				return err
			}
		}
	}
	return nil
}

func (sa *Adapter) SavePolicy(_ model.Model) error {
	return errors.New("not implemented")
}

func (sa *Adapter) AddPolicy(_ string, _ string, _ []string) error {
	return errors.New("not implemented")
}

func (sa *Adapter) RemovePolicy(_ string, _ string, _ []string) error {
	return errors.New("not implemented")
}

func (sa *Adapter) RemoveFilteredPolicy(_ string, _ string, _ int, _ ...string) error {
	return errors.New("not implemented")
}

func (sa *Adapter) SetPolicies(policies map[string]interface{}) {
	sa.policies = policies
}

func (sa *Adapter) GetProjects() []string {
	projects, ok := sa.policies["projects"]
	if ok {
		return projects.([]string)
	}
	return nil
}
