// upstream-audit checks the pinned public domain surface without account access.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/krzysztof-gre/repbridge/internal/garminops"
	"github.com/krzysztof-gre/repbridge/internal/policy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error { return runArgs(os.Args[1:]) }

func runArgs(args []string) error {
	flags := flag.NewFlagSet("upstream-audit", flag.ContinueOnError)
	output := flags.String("output", "", "write the coverage inventory instead of stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected audit arguments")
	}
	command := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/ndeloof/go-garmin")
	directory, err := command.Output()
	if err != nil {
		return fmt.Errorf("find pinned module in Docker toolchain: %w", err)
	}
	files, err := filepath.Glob(filepath.Join(strings.TrimSpace(string(directory)), "pkg", "garmin", "*.go"))
	if err != nil {
		return err
	}
	coverage := garminops.Coverage()
	seen := map[string]bool{}
	type entry struct {
		Method string `json:"method"`
		Action string `json:"action"`
		Write  bool   `json:"write"`
	}
	entries := []entry{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() {
				continue
			}
			ptr, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			receiver, ok := ptr.X.(*ast.Ident)
			if !ok || !strings.HasSuffix(receiver.Name, "Service") {
				continue
			}
			method := strings.TrimSuffix(receiver.Name, "Service") + "." + fn.Name.Name
			tool, ok := coverage[method]
			if !ok {
				return fmt.Errorf("unmapped upstream method: %s", method)
			}
			action, ok := policy.LookupTool(tool)
			if !ok {
				return fmt.Errorf("unclassified coverage target %s", tool)
			}
			seen[method] = true
			entries = append(entries, entry{method, action.Name, action.Write})
		}
	}
	for method := range coverage {
		if !seen[method] {
			return fmt.Errorf("stale upstream mapping: %s", method)
		}
	}
	names := map[string]bool{}
	for _, action := range policy.Actions() {
		if names[action.Name] {
			return fmt.Errorf("duplicate action %s", action.Name)
		}
		names[action.Name] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Method < entries[j].Method })
	report := struct {
		Methods  int     `json:"publicServiceMethods"`
		Actions  int     `json:"classifiedActions"`
		Adapters int     `json:"clientMethodAdapters"`
		Coverage []entry `json:"coverage"`
	}{len(entries), len(names), len(garminops.Specs()), entries}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *output != "" {
		return os.WriteFile(*output, data, 0644)
	}
	_, err = os.Stdout.Write(data)
	return err
}
