package policy

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

// Run inspects policies without a Garmin login or remote request.
func Run(args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "actions" {
		return json.NewEncoder(out).Encode(Actions())
	}
	if len(args) > 0 && args[0] == "check" {
		path := ConfiguredPath()
		if len(args) == 2 {
			path = args[1]
		} else if len(args) != 1 {
			return fmt.Errorf("usage: repbridge policy check [file]")
		}
		p, err := Load(path)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Access policy valid: version %s, %d statements\n", p.Version, len(p.Statement))
		return err
	}
	if len(args) > 0 && args[0] == "explain" {
		flags := flag.NewFlagSet("policy explain", flag.ContinueOnError)
		flags.SetOutput(out)
		action := flags.String("action", "", "Exact action from policy actions")
		name := flags.String("workout-name", "", "Hypothetical workout name; never performs an operation")
		activityStart := flags.String("activity-start-time", "", "Hypothetical activity start, RFC3339 with timezone; never performs an operation")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *action == "" || flags.NArg() != 0 {
			return fmt.Errorf("usage: repbridge policy explain --action NAME [--workout-name NAME] [--activity-start-time RFC3339]")
		}
		p, err := Load(ConfiguredPath())
		if err != nil {
			return err
		}
		attrs := map[string]string{}
		if *activityStart != "" {
			if _, err := parseDate(*activityStart); err != nil {
				return fmt.Errorf("activity-start-time must be RFC3339 with an explicit timezone")
			}
		}
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "workout-name" {
				attrs["garmin:WorkoutName"] = *name
			}
			if f.Name == "activity-start-time" {
				attrs[ActivityStartTimeKey] = *activityStart
			}
		})
		return json.NewEncoder(out).Encode(p.Evaluate(*action, attrs))
	}
	return fmt.Errorf("usage: repbridge policy actions|check|explain")
}
