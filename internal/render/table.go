package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// WriteTable renders a single-line bordered table. When NO_COLOR=1 is set the
// output is plain ASCII and contains no escape sequences.
func WriteTable(w io.Writer, headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return fmt.Errorf("render: WriteTable: headers required")
	}

	if !ColorEnabled() {
		return writeASCIITable(w, headers, rows)
	}

	headerStyle := lipgloss.NewStyle().Bold(true)
	cellStyle := lipgloss.NewStyle()

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if i >= len(widths) {
				break
			}
			if w := lipgloss.Width(c); w > widths[i] {
				widths[i] = w
			}
		}
	}

	var b strings.Builder
	b.WriteString("┌")
	for i, w := range widths {
		b.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			b.WriteString("┬")
		}
	}
	b.WriteString("┐\n")

	b.WriteString("│")
	for i, h := range headers {
		fmt.Fprintf(&b, " %s ", headerStyle.Render(padRight(h, widths[i])))
		b.WriteString("│")
	}
	b.WriteString("\n")

	b.WriteString("├")
	for i, w := range widths {
		b.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			b.WriteString("┼")
		}
	}
	b.WriteString("┤\n")

	for _, row := range rows {
		b.WriteString("│")
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Fprintf(&b, " %s ", cellStyle.Render(padRight(cell, widths[i])))
			b.WriteString("│")
		}
		b.WriteString("\n")
	}

	b.WriteString("└")
	for i, w := range widths {
		b.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			b.WriteString("┴")
		}
	}
	b.WriteString("┘\n")

	_, err := io.WriteString(w, b.String())
	return err
}

func writeASCIITable(w io.Writer, headers []string, rows [][]string) error {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if i >= len(widths) {
				break
			}
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}

	border := func() string {
		parts := make([]string, len(widths))
		for i, w := range widths {
			parts[i] = strings.Repeat("-", w+2)
		}
		return "+" + strings.Join(parts, "+") + "+\n"
	}

	var b strings.Builder
	b.WriteString(border())
	b.WriteString("|")
	for i, h := range headers {
		fmt.Fprintf(&b, " %s |", padRight(h, widths[i]))
	}
	b.WriteString("\n")
	b.WriteString(border())

	for _, row := range rows {
		b.WriteString("|")
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Fprintf(&b, " %s |", padRight(cell, widths[i]))
		}
		b.WriteString("\n")
	}
	b.WriteString(border())

	_, err := io.WriteString(w, b.String())
	return err
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
