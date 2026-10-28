package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedInventoryValidatesReviewedMappings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := runArgs([]string{"--output", path}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Methods  int `json:"publicServiceMethods"`
		Actions  int `json:"classifiedActions"`
		Coverage []struct{ Method, Action string }
	}
	if err := json.Unmarshal(got, &report); err != nil {
		t.Fatal(err)
	}
	if report.Methods == 0 || len(report.Coverage) != report.Methods || report.Actions == 0 {
		t.Fatal("invalid capability inventory")
	}
	for _, args := range [][]string{{"--unknown"}, {"unexpected"}, {"--output", filepath.Join(path, "not-a-dir")}} {
		if err := runArgs(args); err == nil {
			t.Fatal("invalid audit invocation accepted")
		}
	}
}
