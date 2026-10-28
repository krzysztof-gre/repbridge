package policy

import "time"

const ActivityStartTimeKey = "garmin:ActivityStartTime"

func parseDate(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

func dateOperator(op string) bool {
	switch op {
	case "DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals":
		return true
	}
	return false
}

func dateMatches(op, actual string, values []string) bool {
	when, err := parseDate(actual)
	if err != nil {
		return false
	}
	matched := false
	for _, value := range values {
		limit, err := parseDate(value)
		if err != nil {
			return false
		}
		switch op {
		case "DateEquals", "DateNotEquals":
			matched = matched || when.Equal(limit)
		case "DateLessThan":
			matched = matched || when.Before(limit)
		case "DateLessThanEquals":
			matched = matched || !when.After(limit)
		case "DateGreaterThan":
			matched = matched || when.After(limit)
		case "DateGreaterThanEquals":
			matched = matched || !when.Before(limit)
		}
	}
	// Negated operators use NOR for multiple policy values, as in IAM.
	if op == "DateNotEquals" {
		return !matched
	}
	return matched
}
