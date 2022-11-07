package stringadapter

import (
	"bytes"
	"errors"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
)

type Adapter struct {
	Line string
}

func NewAdapter(line string) *Adapter {
	return &Adapter{
		Line: line,
	}
}

func (sa *Adapter) LoadPolicy(model model.Model) error {
	if sa.Line == "" {
		return errors.New("invalid line, line cannot be empty")
	}
	strs := strings.Split(sa.Line, "\n")
	for _, str := range strs {
		if str == "" {
			continue
		}
		_ = persist.LoadPolicyLine(str, model)
	}

	return nil
}

func (sa *Adapter) SavePolicy(model model.Model) error {
	var tmp bytes.Buffer
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			tmp.WriteString(ptype + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			tmp.WriteString(ptype + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}
	sa.Line = strings.TrimRight(tmp.String(), "\n")
	return nil
}

func (sa *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return errors.New("not implemented")
}

func (sa *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	sa.Line = ""
	return nil
}

func (sa *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}
