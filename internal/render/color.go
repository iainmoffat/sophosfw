package render

import "os"

// ColorEnabled reports whether colored output should be emitted. Honors
// NO_COLOR (https://no-color.org) which trumps any terminal detection.
func ColorEnabled() bool {
	return os.Getenv("NO_COLOR") == ""
}
