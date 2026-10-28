package jsondoc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStrictStructure(t *testing.T) {
	for _, s := range []string{`{"x":1,"x":2}`, `{"x":{"a":1,"a":2}}`, `1 2`, `[] {}`, `{"a":}`, `[1,]`, `}`, ``, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)} {
		if _, err := Decode([]byte(s), 1<<20); err == nil {
			t.Fatalf("accepted ambiguous/invalid input %q", s[:min(len(s), 80)])
		}
	}
	for _, s := range []string{`null`, `true`, `12345678901234567890`, `{"a":[1,"x",null,false]}`} {
		v, err := Decode([]byte(s), len(s))
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(v)
		if err != nil || !json.Valid(b) {
			t.Fatal("invalid roundtrip")
		}
	}
	if _, err := Decode([]byte(`{}`), 1); err == nil {
		t.Fatal("size bound ignored")
	}
	if _, err := Decode([]byte("["+strings.Repeat("0,", 100000)+"0]"), 1<<20); err == nil {
		t.Fatal("node bound ignored")
	}
}
func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1,"a":2}`, `[null,true,3]`, `"x"`, `{`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := Decode([]byte(s), 4096)
		if err != nil {
			return
		}
		b, err := json.Marshal(v)
		if err != nil || !json.Valid(b) {
			t.Fatal("accepted invalid JSON")
		}
		if _, err := Decode(b, 1<<20); err != nil {
			t.Fatal(err)
		}
	})
}
