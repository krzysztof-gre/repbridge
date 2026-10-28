package policy

import (
	"fmt"
	"strings"
)

func fieldPath(path string) ([]string, error) {
	if path == "*" {
		return nil, nil
	}
	if !strings.HasPrefix(path, "/") || len(path) > 512 {
		return nil, fmt.Errorf("Fields must be JSON Pointer paths or *")
	}
	parts := strings.Split(path[1:], "/")
	if len(parts) > 32 {
		return nil, fmt.Errorf("field path is too deep")
	}
	for i, p := range parts {
		for j := 0; j < len(p); j++ {
			if p[j] == '~' {
				if j+1 >= len(p) || (p[j+1] != '0' && p[j+1] != '1') {
					return nil, fmt.Errorf("invalid JSON Pointer escape")
				}
				j++
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

// Project returns only selected fields. Top-level arrays are collections of
// records; nested arrays require an explicit * segment. Scalar roots require *.
func (d Decision) Project(value any) (any, error) {
	if !d.Allowed {
		return nil, fmt.Errorf("access denied")
	}
	paths := [][]string{}
	for _, f := range d.Fields {
		if f == "*" {
			return value, nil
		}
		p, err := fieldPath(f)
		if err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	if list, ok := value.([]any); ok {
		out := make([]any, 0, len(list))
		for _, v := range list {
			projected, _ := project(v, paths)
			if projected == nil {
				projected = map[string]any{}
			}
			out = append(out, projected)
		}
		return out, nil
	}
	v, ok := project(value, paths)
	if !ok {
		return map[string]any{}, nil
	}
	return v, nil
}

func project(value any, paths [][]string) (any, bool) {
	for _, p := range paths {
		if len(p) == 0 {
			return value, true
		}
	}
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, child := range v {
			next := [][]string{}
			// A * segment traverses arrays only, never arbitrary object keys.
			for _, p := range paths {
				if len(p) > 0 && p[0] == key {
					next = append(next, p[1:])
				}
			}
			if len(next) > 0 {
				if selected, ok := project(child, next); ok {
					out[key] = selected
				}
			}
		}
		return out, len(out) > 0
	case []any:
		next := [][]string{}
		for _, p := range paths {
			if len(p) > 0 && p[0] == "*" {
				next = append(next, p[1:])
			}
		}
		if len(next) == 0 {
			return nil, false
		}
		out := make([]any, 0, len(v))
		for _, child := range v {
			selected, ok := project(child, next)
			if !ok {
				selected = map[string]any{}
			}
			out = append(out, selected)
		}
		return out, true
	default:
		return nil, false
	}
}
