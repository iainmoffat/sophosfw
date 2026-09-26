package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestScheduleCreateBodyNameGuardsAndDryRun(t *testing.T) {
	d, _ := newRootForTest(t)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	for _, tc := range []struct{ body, want string }{
		{`{"Name":"Y","Type":"Recurring","ScheduleDetails":{"ScheduleDetail":{"Days":"Sunday","StartTime":"00:00","StopTime":"01:00"}}}`, `does not match positional arg`},
		{`{"Name":"  ","Type":"Recurring","ScheduleDetails":{"ScheduleDetail":{"Days":"Sunday","StartTime":"00:00","StopTime":"01:00"}}}`, `body Name must be a non-empty string`},
	} {
		cmd := newScheduleCmd(*d, cat)
		cmd.SetArgs([]string{"create", "X", "--body", tc.body})
		err := cmd.Execute()
		require.ErrorContains(t, err, tc.want)
	}

	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"schedule", "create", "X", "--body", `{"Type":"Recurring","ScheduleDetails":{"ScheduleDetail":{"Days":"Sunday","StartTime":"00:00","StopTime":"01:00"}}}`, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"applied": false`)
}

type fakeScheduleCommandClient struct{ referenced bool }

func (f fakeScheduleCommandClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) > 0 {
		if op, ok := env.Operations[0].(sophos.GetOp); ok {
			switch op.XMLTag {
			case "Schedule":
				resp.Body["Schedule"] = []json.RawMessage{json.RawMessage(`{"Name":"Night","Type":"Recurring"}`)}
			case "FirewallRule":
				if f.referenced {
					resp.Body["FirewallRule"] = []json.RawMessage{json.RawMessage(`{"Name":"Allow","NetworkPolicy":{"Schedule":"Night"}}`)}
				}
			}
		}
	}
	return resp, nil
}
func (fakeScheduleCommandClient) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func TestScheduleDeleteSurfacesReferenceGuard(t *testing.T) {
	d, _ := newRootForTest(t)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client { return fakeScheduleCommandClient{referenced: true} }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	root := NewRoot(*d)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "delete", "Night", "--yes", "--ignore-diff-hash"})
	err := root.Execute()
	require.ErrorContains(t, err, "referenced by firewall rules")
}

func TestScheduleShowWithReferencesJSON(t *testing.T) {
	d, _ := newRootForTest(t)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client { return fakeScheduleCommandClient{referenced: true} }
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "show", "Night", "--json", "--with-references"})
	require.NoError(t, root.Execute())
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &envelope))
	references, ok := envelope["references"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []any{"Allow"}, references["FirewallRule"])
	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, data, "references")
}

func TestScheduleListColumnsOverride(t *testing.T) {
	d, _ := newRootForTest(t)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client { return fakeScheduleCommandClient{} }
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "list", "--columns", "Name,Periods"})
	t.Setenv("NO_COLOR", "1")
	require.NoError(t, root.Execute())
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 5)
	headerCells := strings.Split(strings.Trim(lines[1], "| "), "|")
	for i := range headerCells {
		headerCells[i] = strings.TrimSpace(headerCells[i])
	}
	require.Equal(t, []string{"NAME", "PERIODS"}, headerCells)
}

func TestScheduleShowTextFormat(t *testing.T) {
	multi := map[string]any{
		"Name": "Night", "Type": "Recurring", "Description": "Weekend cover",
		"ScheduleDetails": map[string]any{"ScheduleDetail": []any{
			map[string]any{"Days": "Sunday", "StartTime": "00:00", "StopTime": "23:59"},
			map[string]any{"Days": "Saturday", "StartTime": "00:00", "StopTime": "23:59"},
		}},
	}
	hash, err := svc.DiffHash(multi)
	require.NoError(t, err)
	d, _ := newRootForTest(t)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client {
		return fakeScheduleShowClient{schedule: multi, rule: map[string]any{"Name": "AllowRule", "NetworkPolicy": map[string]any{"Schedule": "Night"}}}
	}
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "show", "Night", "--with-references"})
	require.NoError(t, root.Execute())
	require.Equal(t, fmt.Sprintf("Name: Night\nType: Recurring\nDescription: Weekend cover\nPeriods:\n  Sunday 00:00-23:59\n  Saturday 00:00-23:59\nDiffHash: %s\nReferenced by FirewallRule: AllowRule\n", hash), out.String())

	withoutDescription := map[string]any{"Name": "Night", "Type": "OneTime"}
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client {
		return fakeScheduleShowClient{schedule: withoutDescription}
	}
	root = NewRoot(*d)
	out.Reset()
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "show", "Night", "--with-references"})
	require.NoError(t, root.Execute())
	withoutDescriptionHash, err := svc.DiffHash(withoutDescription)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("Name: Night\nType: OneTime\nPeriods:\nDiffHash: %s\nReferenced by FirewallRule: none\n", withoutDescriptionHash), out.String())
}

type fakeScheduleShowClient struct {
	schedule map[string]any
	rule     map[string]any
	ruleErr  error
}

func (f fakeScheduleShowClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	op, ok := env.Operations[0].(sophos.GetOp)
	if !ok {
		return resp, nil
	}
	if op.XMLTag == "FirewallRule" && f.ruleErr != nil {
		return nil, f.ruleErr
	}
	var value map[string]any
	switch op.XMLTag {
	case "Schedule":
		value = f.schedule
	case "FirewallRule":
		value = f.rule
	default:
		return resp, nil
	}
	if value != nil {
		b, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		resp.Body[op.XMLTag] = []json.RawMessage{b}
	}
	return resp, nil
}
func (fakeScheduleShowClient) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func TestScheduleShowTextReportsReferenceScanErrorAndKeepsRecord(t *testing.T) {
	record := map[string]any{"Name": "Night", "Type": "Recurring"}
	hash, err := svc.DiffHash(record)
	require.NoError(t, err)
	d, _ := newRootForTest(t)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client {
		return fakeScheduleShowClient{schedule: record, ruleErr: errors.New("firewall rule query denied")}
	}
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "show", "Night", "--with-references"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "Name: Night\nType: Recurring\nPeriods:\n")
	require.Contains(t, out.String(), fmt.Sprintf("DiffHash: %s\n", hash))
	require.Contains(t, out.String(), "Referenced by FirewallRule: none\n")
	require.Contains(t, out.String(), "Reference scan errors: generic: firewall rule query denied\n")
}

func TestScheduleShowTextReportsSkippedReferenceRecords(t *testing.T) {
	record := map[string]any{"Name": "Night", "Type": "Recurring"}
	d, _ := newRootForTest(t)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client {
		// A matching rule with no Name: the delete guard refuses on it, so
		// the text view must not read as a clean "none".
		return fakeScheduleShowClient{schedule: record, rule: map[string]any{"Name": "", "NetworkPolicy": map[string]any{"Schedule": "Night"}}}
	}
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "show", "Night", "--with-references"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "Referenced by FirewallRule: none\n")
	require.Contains(t, out.String(), "Reference scan incomplete: 1 FirewallRule records could not be examined; delete will be refused\n")
}
