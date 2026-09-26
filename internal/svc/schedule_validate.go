package svc

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// scheduleDays is the closed, case-sensitive Days vocabulary, verified
// against SFOS on testvm 2026-09-26.
var scheduleDays = []string{
	"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
	"Week Days", "Weekdays Including Saturday", "All Days of week",
}

var scheduleTimePattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):(00|15|30|45)$`)

var scheduleNextDay = map[string]string{
	"Sunday": "Monday", "Monday": "Tuesday", "Tuesday": "Wednesday",
	"Wednesday": "Thursday", "Thursday": "Friday", "Friday": "Saturday",
	"Saturday": "Sunday",
}

var scheduleAggregateDays = map[string]bool{
	"Week Days":                   true,
	"Weekdays Including Saturday": true,
	"All Days of week":            true,
}

// validateScheduleBody checks a create/update body against the SFOS
// Schedule rules and returns a NEW normalized map: _diffHash removed,
// ScheduleDetails.ScheduleDetail always a []any of map[string]any. The
// caller's map is never mutated. Errors wrap sophos.ErrInvalidRequest.
func validateScheduleBody(body map[string]any) (map[string]any, error) {
	name, ok := body["Name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return nil, scheduleBodyError("Name must be a non-empty string")
	}
	typeName, ok := body["Type"].(string)
	if !ok || typeName != "Recurring" {
		if !ok {
			typeName = ""
		}
		return nil, scheduleBodyError(fmt.Sprintf("only Recurring schedules are writable (got %q)", typeName))
	}

	details, ok := body["ScheduleDetails"].(map[string]any)
	if !ok {
		return nil, scheduleBodyError("ScheduleDetails must be an object containing ScheduleDetail")
	}
	detailValue, ok := details["ScheduleDetail"]
	if !ok {
		return nil, scheduleBodyError("ScheduleDetails must be an object containing ScheduleDetail")
	}

	var inputPeriods []map[string]any
	switch value := detailValue.(type) {
	case map[string]any:
		inputPeriods = []map[string]any{value}
	case []any:
		if len(value) == 0 {
			return nil, scheduleBodyError("ScheduleDetail must be an object or a non-empty array of objects")
		}
		inputPeriods = make([]map[string]any, len(value))
		for i, period := range value {
			periodMap, ok := period.(map[string]any)
			if !ok {
				return nil, scheduleBodyError("ScheduleDetail must be an object or a non-empty array of objects")
			}
			inputPeriods[i] = periodMap
		}
	default:
		return nil, scheduleBodyError("ScheduleDetail must be an object or a non-empty array of objects")
	}

	periods := make([]map[string]any, len(inputPeriods))
	for i, period := range inputPeriods {
		index := i + 1
		values := make(map[string]string, 3)
		for _, key := range []string{"Days", "StartTime", "StopTime"} {
			value, ok := period[key].(string)
			if !ok {
				return nil, scheduleBodyError(fmt.Sprintf("period %d: %s must be a string", index, key))
			}
			values[key] = value
		}

		days, start, stop := values["Days"], values["StartTime"], values["StopTime"]
		if !validScheduleDay(days) {
			if suggestion := scheduleDaySuggestion(days); suggestion != "" {
				return nil, scheduleBodyError(fmt.Sprintf("period %d: Days %q is not a valid SFOS value (did you mean %q?)", index, days, suggestion))
			}
			return nil, scheduleBodyError(fmt.Sprintf("period %d: Days %q is not a valid SFOS value; valid values: %s", index, days, strings.Join(scheduleDays, ", ")))
		}
		if !scheduleTimePattern.MatchString(start) {
			return nil, scheduleBodyError(fmt.Sprintf("period %d: StartTime %q must be HH:MM on a 15-minute boundary (:00, :15, :30, :45)", index, start))
		}
		stopValid := scheduleTimePattern.MatchString(stop) || stop == "23:59"
		if !stopValid {
			return nil, scheduleBodyError(fmt.Sprintf("period %d: StopTime %q must be HH:MM on a 15-minute boundary (:00, :15, :30, :45) or 23:59", index, stop))
		}
		if start == stop {
			return nil, scheduleBodyError(fmt.Sprintf("period %d is empty (StartTime equals StopTime)", index))
		}
		if start > stop {
			if scheduleAggregateDays[days] {
				return nil, scheduleBodyError(fmt.Sprintf("period %d crosses midnight; SFOS rejects this. %q is an aggregate: list the individual days and split each at midnight (<day> %s-23:59 plus <next day> 00:00-%s)", index, days, start, stop))
			}
			if stop == "00:00" {
				return nil, scheduleBodyError(fmt.Sprintf("period %d crosses midnight; SFOS rejects this. Use %s %s-23:59 instead", index, days, start))
			}
			return nil, scheduleBodyError(fmt.Sprintf("period %d crosses midnight; SFOS rejects this. Split it into %s %s-23:59 and %s 00:00-%s", index, days, start, scheduleNextDay[days], stop))
		}

		periods[i] = make(map[string]any, len(period))
		for key, value := range period {
			periods[i][key] = value
		}
	}

	result := make(map[string]any, len(body))
	for key, value := range body {
		if key != "_diffHash" && key != "ScheduleDetails" {
			result[key] = value
		}
	}
	normalizedDetails := make(map[string]any, len(details))
	for key, value := range details {
		if key != "ScheduleDetail" {
			normalizedDetails[key] = value
		}
	}
	normalizedDetails["ScheduleDetail"] = anyPeriods(periods)
	result["ScheduleDetails"] = normalizedDetails
	return result, nil
}

func anyPeriods(periods []map[string]any) []any {
	result := make([]any, len(periods))
	for i := range periods {
		result[i] = periods[i]
	}
	return result
}

func validScheduleDay(day string) bool {
	for _, valid := range scheduleDays {
		if day == valid {
			return true
		}
	}
	return false
}

func scheduleDaySuggestion(day string) string {
	for _, valid := range scheduleDays {
		if strings.EqualFold(day, valid) {
			return valid
		}
	}
	return ""
}

func scheduleBodyError(message string) error {
	return fmt.Errorf("%w: %s", sophos.ErrInvalidRequest, message)
}
