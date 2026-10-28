// Package jsondoc decodes bounded JSON without ambiguous duplicate object keys.
package jsondoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func Decode(data []byte, maxBytes int) (any, error) {
	if len(data) == 0 || len(data) > maxBytes {
		return nil, fmt.Errorf("JSON size is outside the allowed range")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	v, err := read(d, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("JSON must contain exactly one value")
	}
	return v, nil
}

func read(d *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 64 || *nodes > 100000 {
		return nil, fmt.Errorf("JSON structure is too complex")
	}
	t, err := d.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON")
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, fmt.Errorf("invalid JSON object")
			}
			k, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("invalid JSON object key")
			}
			if _, exists := m[k]; exists {
				return nil, fmt.Errorf("duplicate JSON object key")
			}
			v, err := read(d, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("invalid JSON object")
		}
		return m, nil
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, err := read(d, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("invalid JSON array")
		}
		return a, nil
	default:
		if _, ok := t.(json.Delim); ok {
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
		return t, nil
	}
}
