// Package authorization evaluates scope/action permissions without identity or
// persistence dependencies. Callers resolve actual resources and supported actions.
package authorization

import (
	"errors"
	"strings"
	"unicode"
)

var (
	ErrInvalid = errors.New("invalid authorization description")
	ErrDenied  = errors.New("required permission is absent")
)

type Scope struct {
	Pattern string `json:"pattern"`
}

type Permission struct {
	Scope   Scope    `json:"scope"`
	Actions []string `json:"actions"`
}

// Requirement is one concrete operation, using list/get rather than the read
// permission shorthand. Target and action never contain wildcard selectors.
type Requirement struct {
	Target string
	Action string
}

type rule struct {
	scope   []string
	actions [][]string
}

// Check requires every target/action pair to be covered by an applicable
// permission. An allowed result describes this bounded operation only.
func Check(permissions []Permission, requirements ...Requirement) error {
	if len(requirements) == 0 {
		return ErrInvalid
	}
	rules := make([]rule, 0, len(permissions))
	for _, permission := range permissions {
		scope, err := segments(permission.Scope.Pattern, '/', true)
		if err != nil || len(permission.Actions) == 0 {
			return ErrInvalid
		}
		entry := rule{scope: scope}
		for _, action := range permission.Actions {
			pattern, err := segments(action, '.', true)
			if err != nil {
				return err
			}
			if pattern[len(pattern)-1] == "read" {
				for _, verb := range []string{"list", "get"} {
					expanded := append([]string(nil), pattern...)
					expanded[len(expanded)-1] = verb
					entry.actions = append(entry.actions, expanded)
				}
			} else {
				entry.actions = append(entry.actions, pattern)
			}
		}
		rules = append(rules, entry)
	}
	allowed := true
	for _, requirement := range requirements {
		target, err := segments(requirement.Target, '/', false)
		if err != nil {
			return err
		}
		action, err := segments(requirement.Action, '.', false)
		if err != nil || action[len(action)-1] == "read" {
			return ErrInvalid
		}
		matched := false
		for _, entry := range rules {
			if !matches(entry.scope, target) {
				continue
			}
			for _, candidate := range entry.actions {
				if matches(candidate, action) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		allowed = allowed && matched
	}
	if !allowed {
		return ErrDenied
	}
	return nil
}

func segments(value string, separator rune, pattern bool) ([]string, error) {
	if value == "" {
		return nil, ErrInvalid
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) || strings.ContainsRune(`?[]{}()|^$+\`, char) || separator == '.' && char == '/' {
			return nil, ErrInvalid
		}
	}
	parts := strings.Split(value, string(separator))
	deep := false
	for _, part := range parts {
		if part == "" {
			return nil, ErrInvalid
		}
		if strings.Contains(part, "*") {
			if !pattern || part != "*" && part != "**" || part == "**" && deep {
				return nil, ErrInvalid
			}
			deep = deep || part == "**"
		}
	}
	return parts, nil
}

func matches(pattern, target []string) bool {
	deep := -1
	for index, part := range pattern {
		if part == "**" {
			deep = index
			break
		}
	}
	if deep < 0 {
		return len(pattern) == len(target) && matchesSingle(pattern, target)
	}
	suffix := len(pattern) - deep - 1
	return len(target) >= len(pattern)-1 &&
		matchesSingle(pattern[:deep], target[:deep]) &&
		matchesSingle(pattern[deep+1:], target[len(target)-suffix:])
}

func matchesSingle(pattern, target []string) bool {
	for index, part := range pattern {
		if part != "*" && part != target[index] {
			return false
		}
	}
	return true
}
