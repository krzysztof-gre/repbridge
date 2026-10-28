package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/krzysztof-gre/repbridge/internal/auth"
	"github.com/krzysztof-gre/repbridge/internal/garminops"
	"github.com/krzysztof-gre/repbridge/internal/policy"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

var errClientArguments = fmt.Errorf("invalid native client arguments")

var readerType = reflect.TypeFor[io.Reader]()
var dateType = reflect.TypeFor[garmin.Date]()
var safePathToken = regexp.MustCompile(`^[A-Za-z0-9_-]{0,128}$`)

// Only the reviewed catalogue selects methods. Caller input cannot select a
// service, method, URL or HTTP verb. Upstream still owns every Garmin request.
func methodValue(client *garmin.Client, spec garminops.Spec) (reflect.Value, error) {
	field := reflect.ValueOf(client).Elem().FieldByName(spec.Service)
	if !field.IsValid() {
		return reflect.Value{}, fmt.Errorf("unknown Garmin service")
	}
	method := field.MethodByName(spec.Method)
	if !method.IsValid() {
		return reflect.Value{}, fmt.Errorf("unknown Garmin method")
	}
	t := method.Type()
	if t.NumIn() != len(spec.Params)+1 || t.In(0) != reflect.TypeFor[context.Context]() || t.NumOut() < 1 || t.Out(t.NumOut()-1) != reflect.TypeFor[error]() {
		return reflect.Value{}, fmt.Errorf("Garmin method signature changed")
	}
	return method, nil
}

func clientMethodSchema(spec garminops.Spec) (any, error) {
	// Zero-valued services suffice for method type inspection; no account I/O.
	method, err := methodValue(&garmin.Client{}, spec)
	if err != nil {
		return nil, err
	}
	fields := make([]reflect.StructField, len(spec.Params))
	for i, name := range spec.Params {
		t := method.Type().In(i + 1)
		if t == readerType {
			t = reflect.TypeFor[string]()
		}
		tag := reflect.StructTag(`json:"` + name + `" jsonschema:"required"`)
		if t.Kind() == reflect.Pointer || t == reflect.TypeFor[time.Time]() {
			tag = reflect.StructTag(`json:"` + name + `,omitempty"`)
		}
		fields[i] = reflect.StructField{Name: fmt.Sprintf("Arg%d", i), Type: t, Tag: tag}
	}
	reflector := jsonschema.Reflector{Anonymous: true, ExpandedStruct: false, RequiredFromJSONSchemaTags: true,
		Mapper: func(t reflect.Type) *jsonschema.Schema {
			switch t {
			case reflect.TypeFor[garmin.WeightUnit]():
				return &jsonschema.Schema{Type: "string", Enum: []any{string(garmin.Kilograms), string(garmin.Pounds)}}
			case reflect.TypeFor[garmin.GoalStatus]():
				return &jsonschema.Schema{Type: "string", Enum: []any{string(garmin.GoalsActive), string(garmin.GoalsFuture), string(garmin.GoalsPast)}}
			case reflect.TypeFor[garmin.ExportFormat]():
				return &jsonschema.Schema{Type: "string", Enum: []any{string(garmin.ExportTCX), string(garmin.ExportGPX), string(garmin.ExportKML), string(garmin.ExportCSV)}}
			case reflect.TypeFor[garmin.ProgressMetric]():
				return &jsonschema.Schema{Type: "string", Enum: []any{string(garmin.ProgressDistance), string(garmin.ProgressDuration), string(garmin.ProgressMovingDuration), string(garmin.ProgressElevationGain)}}
			}
			if t == dateType {
				return &jsonschema.Schema{Type: "string", Format: "date", Pattern: `^\d{4}-\d{2}-\d{2}$`}
			}
			return nil
		}}
	return reflector.ReflectFromType(reflect.StructOf(fields)), nil
}

func installClientMethods(server *sdk.Server, p *policy.Policy, gate chan struct{}) error {
	seen := map[string]bool{}
	for _, spec := range garminops.Specs() {
		if seen[spec.Name] {
			return fmt.Errorf("duplicate client-method action")
		}
		seen[spec.Name] = true
		schema, err := clientMethodSchema(spec)
		if err != nil {
			return fmt.Errorf("catalogue %s: %w", spec.Name, err)
		}
		desc := spec.Description + " " + fmt.Sprintf("Call the pinned upstream %s.%s method. Arguments use its native JSON field names. Optional options default to a bounded page (maximum 100). Dates are YYYY-MM-DD, timestamps RFC3339. Scalar results are wrapped as {value:...}. File inputs are base64 data, never local paths; binary outputs are {encoding:base64,data:...}, subject to field projection and size limits.", spec.Service, spec.Method)
		if spec.Name == "execute_graphql" {
			desc += " HIGH RISK: arbitrary GraphQL may mutate data and read across domains. Always classified as a destructive write. This separate grant does not inherit per-activity date or workout-name restrictions; Denies on other named actions do not constrain GraphQL documents. Denied in shipped policies."
		}
		if spec.Activity == "collection" {
			desc += " Activity records are filtered individually when activity-date conditions apply."
		}
		if spec.Name == "delete_all_weigh_ins" {
			desc += " Deletes every weigh-in for one date; the upstream composite may partially complete before failure. Reconcile with read tools before retrying."
		}
		if err := install(server, p, gate, &sdk.Tool{Name: spec.Name, Description: desc, InputSchema: schema}, func(ctx context.Context, args map[string]any) (any, error) {
			return invokeClientMethod(ctx, p, spec, args)
		}); err != nil {
			return fmt.Errorf("install %s: %w", spec.Name, err)
		}
	}
	return nil
}

func invokeClientMethod(ctx context.Context, p *policy.Policy, spec garminops.Spec, args map[string]any) (any, error) {
	// Decode and bound all arguments before acquiring credentials or making calls.
	values, err := clientMethodArguments(spec, args)
	if err != nil {
		return nil, errClientArguments
	}
	a, _ := policy.LookupTool(spec.Name)
	read := func(client *garmin.Client) (any, error) {
		if err := checkOwnedReferences(ctx, client, args); err != nil {
			return nil, err
		}
		method, err := methodValue(client, spec)
		if err != nil {
			return nil, err
		}
		input := append([]reflect.Value{reflect.ValueOf(ctx)}, values...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		output := method.Call(input)
		if last := output[len(output)-1]; !last.IsNil() {
			return nil, last.Interface().(error)
		}
		if len(output) == 1 {
			return map[string]any{"completed": true}, nil
		}
		if len(output) == 2 {
			value := output[0].Interface()
			if spec.Name == "execute_graphql" {
				raw, ok := value.(json.RawMessage)
				if !ok {
					return nil, fmt.Errorf("invalid GraphQL response")
				}
				var envelope map[string]json.RawMessage
				if json.Unmarshal(raw, &envelope) != nil {
					return nil, fmt.Errorf("invalid GraphQL response")
				}
				if _, present := envelope["data"]; !present {
					return nil, fmt.Errorf("GraphQL response has no data envelope")
				}
				if errors, ok := envelope["errors"]; ok {
					text := strings.TrimSpace(string(errors))
					if text != "null" && text != "[]" {
						return nil, fmt.Errorf("GraphQL operation failed; outcome may be partial")
					}
				}
			}

			// RawMessage must remain JSON; it is also a named []byte type.
			if data, ok := value.([]byte); ok {
				return map[string]any{"encoding": "base64", "data": base64.StdEncoding.EncodeToString(data)}, nil
			}
			kind := reflect.TypeOf(value)
			if kind != nil && (kind.Kind() == reflect.Int || kind.Kind() == reflect.Int64 || kind.Kind() == reflect.String || kind.Kind() == reflect.Bool || kind.Kind() == reflect.Float64) {
				return map[string]any{"value": value}, nil
			}
			return value, nil
		}
		if len(spec.Results) != len(output)-1 {
			return nil, fmt.Errorf("unmapped multi-result method")
		}
		result := map[string]any{}
		for i, name := range spec.Results {
			result[name] = output[i].Interface()
		}
		return result, nil
	}
	if a.ActivityStartTime {
		return invokeActivity(ctx, p, a, args, read)
	}
	var result any
	err = auth.WithClient(ctx, func(client *garmin.Client) error {
		attrs := map[string]string{}
		if a.WorkoutName && p.NeedsWorkoutName(a.Name) {
			id, err := integer(args["workout_id"])
			if err != nil {
				return errDenied
			}
			name, err := existingWorkoutName(ctx, client, id)
			if err != nil {
				return err
			}
			attrs["garmin:WorkoutName"] = name
		}
		d := p.Evaluate(a.Name, attrs)
		if !d.Allowed {
			return errDenied
		}
		value, err := read(client)
		if err != nil {
			return err
		}
		result = authorizedResult{value: value, decision: d}
		return nil
	})
	return result, err
}

func clientMethodArguments(spec garminops.Spec, args map[string]any) ([]reflect.Value, error) {
	method, err := methodValue(&garmin.Client{}, spec)
	if err != nil {
		return nil, err
	}
	values := make([]reflect.Value, len(spec.Params))
	for i, name := range spec.Params {
		t := method.Type().In(i + 1)
		value, present := args[name]
		if t == readerType {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("base64 string required")
			}
			data, err := base64.StdEncoding.Strict().DecodeString(text)
			if err != nil || len(data) == 0 || len(data) > 512<<10 {
				return nil, fmt.Errorf("file input must be bounded base64")
			}
			values[i] = reflect.ValueOf(bytes.NewReader(data))
			continue
		}
		if !present && t.Kind() != reflect.Pointer && t != reflect.TypeFor[time.Time]() {
			return nil, fmt.Errorf("argument required")
		}
		if t == dateType {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("date required")
			}
			if _, err := time.Parse("2006-01-02", text); err != nil {
				return nil, fmt.Errorf("invalid date")
			}
		}
		target := reflect.New(t)
		if present {
			data, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(target.Interface()); err != nil {
				return nil, fmt.Errorf("invalid native argument")
			}
		}
		decoded := target.Elem()
		// Optional native options never inherit the library's unbounded/1000-row defaults.
		if t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct && decoded.IsNil() {
			decoded.Set(reflect.New(t.Elem()))
		}
		if name == "options" {
			if err := boundNativeOptions(decoded); err != nil {
				return nil, err
			}
		}
		if t.Kind() == reflect.Int64 && decoded.Int() <= 0 {
			return nil, fmt.Errorf("positive identifier required")
		}
		if name == "year" && (decoded.Int() < 1970 || decoded.Int() > 2200) {
			return nil, fmt.Errorf("year out of bounds")
		}
		if name == "month" && (decoded.Int() < 1 || decoded.Int() > 12) {
			return nil, fmt.Errorf("month out of bounds")
		}
		if name == "weeks" && (decoded.Int() < 1 || decoded.Int() > 4) {
			return nil, fmt.Errorf("weekly range exceeds 28 days")
		}
		if name == "filename" {
			text, ok := value.(string)
			if !ok || text == "" || len(text) > 128 || filepath.Base(text) != text || strings.ContainsAny(text, "\\\r\n") || text == "." || text == ".." {
				return nil, fmt.Errorf("filename must be a basename")
			}
		}
		switch name {
		case "gear_uuid", "sport", "aggregation", "granularity", "format", "status", "unit":
			if !safePathToken.MatchString(fmt.Sprint(value)) {
				return nil, fmt.Errorf("invalid path or enum token")
			}
		case "hole_numbers":
			text, ok := value.(string)
			if !ok || len(text) > 64 {
				return nil, fmt.Errorf("invalid hole selection")
			}
			// The upstream method validates its own comma/dash selection syntax.

		}
		values[i] = decoded
	}
	return values, nil
}

func boundNativeOptions(v reflect.Value) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return boundNativeOptions(v.Elem())
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := v.Type().Field(i).Name
		if field.Kind() == reflect.Struct {
			if err := boundNativeOptions(field); err != nil {
				return err
			}
		}
		if field.Kind() == reflect.Int {
			switch name {
			case "Limit":
				if field.Int() == 0 {
					field.SetInt(100)
				}
				if field.Int() < 1 || field.Int() > 100 {
					return fmt.Errorf("page limit outside 1..100")
				}
			case "Start":
				if field.Int() < 0 || field.Int() > 10000 {
					return fmt.Errorf("offset outside bounds")
				}
			case "MaxChartSize", "MaxPolylineSize", "MaxSize":
				if name == "MaxChartSize" && field.Int() == 0 {
					field.SetInt(1000)
				}
				if field.Int() < 0 || field.Int() > 1000 {
					return fmt.Errorf("sample size outside bounds")
				}
			}
		}
	}
	// Activity search options carry their own date range rather than top-level dates.
	start, end := v.FieldByName("StartDate"), v.FieldByName("EndDate")
	if start.IsValid() && end.IsValid() && start.Type() == dateType && end.Type() == dateType {
		a, b := start.Interface().(garmin.Date), end.Interface().(garmin.Date)
		if !a.IsZero() || !b.IsZero() {
			if b.IsZero() {
				b = garmin.DateOf(time.Now().UTC())
			}
			if a.IsZero() {
				a = b.AddDays(-7)
			}
			if a.After(b) || a.DaysUntil(b) > 31 {
				return fmt.Errorf("search range exceeds 31 days")
			}
			start.Set(reflect.ValueOf(a))
			end.Set(reflect.ValueOf(b))
		}
	}
	return nil
}

func checkOwnedReferences(ctx context.Context, client *garmin.Client, args map[string]any) error {
	if value, ok := args["user_profile_id"]; ok {
		id, err := integer(value)
		if err != nil {
			return errDenied
		}
		profile, err := client.UserProfile.SocialProfile(ctx)
		if err != nil {
			return err
		}
		if profile == nil || profile.ProfileID != id {
			return errDenied
		}
	}
	if value, ok := args["device_id"]; ok {
		id, err := integer(value)
		if err != nil {
			return errDenied
		}
		devices, err := client.Devices.List(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, device := range devices {
			if device.DeviceID == id {
				found = true
				break
			}
		}
		if !found {
			return errDenied
		}
	}
	if value, ok := args["gear_uuid"]; ok {
		profile, err := client.UserProfile.SocialProfile(ctx)
		if err != nil {
			return err
		}
		if profile == nil {
			return errDenied
		}
		gear, err := client.Gear.List(ctx, profile.ProfileID)
		if err != nil {
			return err
		}
		found := false
		for _, item := range gear {
			if item.UUID == value {
				found = true
				break
			}
		}
		if !found {
			return errDenied
		}
	}
	return nil
}
