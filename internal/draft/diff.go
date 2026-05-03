package draft

import (
	"bytes"
	"fmt"
	"strings"
)

// UnifiedDiff returns a unified-diff string comparing aBody to bBody,
// labeled with aLabel and bLabel. Returns "" if the inputs are
// byte-identical.
//
// Uses an LCS table to compute the minimal edit script. Output format
// matches `diff -u`: header lines `--- aLabel` / `+++ bLabel`, then
// hunks `@@ -a,L +b,L @@` with 3 lines of context, ` ` for context
// lines, `-` for removed lines, `+` for added lines.
//
// Complexity: O(n*m) in line counts. Suitable for YAML bodies up to a
// few thousand lines; firewall rules in practice are <300 lines.
func UnifiedDiff(aBody, bBody []byte, aLabel, bLabel string) string {
	if bytes.Equal(aBody, bBody) {
		return ""
	}
	a := splitLines(aBody)
	b := splitLines(bBody)
	ops := lcsDiff(a, b)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--- %s\n", aLabel)
	fmt.Fprintf(&buf, "+++ %s\n", bLabel)

	hunks := groupHunks(ops, 3)
	for _, h := range hunks {
		fmt.Fprintf(&buf, "@@ -%d,%d +%d,%d @@\n", h.aStart+1, h.aLen, h.bStart+1, h.bLen)
		for _, op := range h.ops {
			switch op.kind {
			case '-':
				buf.WriteString("-")
			case '+':
				buf.WriteString("+")
			case ' ':
				buf.WriteString(" ")
			}
			buf.WriteString(op.line)
			buf.WriteByte('\n')
		}
	}
	return buf.String()
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.Split(s, "\n")
}

type diffOp struct {
	kind byte
	line string
}

func lcsDiff(a, b []string) []diffOp {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				lcs[i][j] = lcs[i-1][j-1] + 1
			} else if lcs[i-1][j] >= lcs[i][j-1] {
				lcs[i][j] = lcs[i-1][j]
			} else {
				lcs[i][j] = lcs[i][j-1]
			}
		}
	}
	var ops []diffOp
	i, j := n, m
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && a[i-1] == b[j-1]:
			ops = append([]diffOp{{kind: ' ', line: a[i-1]}}, ops...)
			i--
			j--
		case j > 0 && (i == 0 || lcs[i][j-1] >= lcs[i-1][j]):
			ops = append([]diffOp{{kind: '+', line: b[j-1]}}, ops...)
			j--
		default:
			ops = append([]diffOp{{kind: '-', line: a[i-1]}}, ops...)
			i--
		}
	}
	return ops
}

type hunk struct {
	aStart, aLen int
	bStart, bLen int
	ops          []diffOp
}

func groupHunks(ops []diffOp, context int) []hunk {
	type change struct {
		start, end int
	}
	var changes []change
	i := 0
	for i < len(ops) {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := i
		for i < len(ops) && ops[i].kind != ' ' {
			i++
		}
		changes = append(changes, change{start: start, end: i})
	}
	merged := []change{}
	for _, c := range changes {
		s := c.start - context
		if s < 0 {
			s = 0
		}
		e := c.end + context
		if e > len(ops) {
			e = len(ops)
		}
		if len(merged) > 0 && merged[len(merged)-1].end >= s {
			if e > merged[len(merged)-1].end {
				merged[len(merged)-1].end = e
			}
		} else {
			merged = append(merged, change{start: s, end: e})
		}
	}
	aPos, bPos := 0, 0
	prev := 0
	var hunks []hunk
	for _, c := range merged {
		for k := prev; k < c.start; k++ {
			switch ops[k].kind {
			case ' ':
				aPos++
				bPos++
			case '-':
				aPos++
			case '+':
				bPos++
			}
		}
		hunkOps := ops[c.start:c.end]
		var aLen, bLen int
		for _, op := range hunkOps {
			switch op.kind {
			case ' ':
				aLen++
				bLen++
			case '-':
				aLen++
			case '+':
				bLen++
			}
		}
		hunks = append(hunks, hunk{
			aStart: aPos,
			aLen:   aLen,
			bStart: bPos,
			bLen:   bLen,
			ops:    hunkOps,
		})
		for _, op := range hunkOps {
			switch op.kind {
			case ' ':
				aPos++
				bPos++
			case '-':
				aPos++
			case '+':
				bPos++
			}
		}
		prev = c.end
	}
	return hunks
}
