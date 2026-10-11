package spec

import (
	"fmt"
	"time"
)

// TimestampLayout is the datetime format of DID Resolution v1.0 §3.1 and
// DID Core 1.0 §7.1.3: an XML datetime adjusted to UTC without sub-second
// decimal precision, for example 2020-12-20T19:17:47Z.
const TimestampLayout = "2006-01-02T15:04:05Z"

// FormatTimestamp converts t to UTC, truncates it to whole seconds and
// formats it with TimestampLayout.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(TimestampLayout)
}

// ParseTimestamp parses s in exactly TimestampLayout. An offset other than Z,
// a sub-second fraction or any other form is rejected, not corrected.
func ParseTimestamp(s string) (time.Time, error) {
	if len(s) != len(TimestampLayout) || s[len(s)-1] != 'Z' {
		return time.Time{}, fmt.Errorf("spec: %q is not a UTC datetime without sub-second precision", s)
	}
	t, err := time.Parse(TimestampLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("spec: invalid datetime %q: %w", s, err)
	}
	return t, nil
}

// IsTimestamp reports whether t can be written in TimestampLayout without
// loss: it has no sub-second part. Any location is accepted, because writing
// converts to UTC.
func IsTimestamp(t time.Time) bool {
	return t.Nanosecond() == 0 && !t.IsZero()
}
