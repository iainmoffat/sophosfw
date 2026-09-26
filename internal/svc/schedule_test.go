package svc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeScheduleClient struct {
	schedule               map[string]any
	firewallRules          []map[string]any
	failFirewall           bool
	failScheduleAfterApply bool
	scheduleGets           int
	tags                   []string
	sent                   [][]byte
}

func (f *fakeScheduleClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	for _, operation := range env.Operations {
		get, ok := operation.(sophos.GetOp)
		if !ok {
			continue
		}
		f.tags = append(f.tags, get.XMLTag)
		switch get.XMLTag {
		case "Schedule":
			f.scheduleGets++
			if f.failScheduleAfterApply && f.scheduleGets >= 1 {
				return nil, errors.New("refetch failed")
			}
			if f.schedule != nil {
				raw, _ := json.Marshal(f.schedule)
				resp.Body["Schedule"] = []json.RawMessage{raw}
			}
		case "FirewallRule":
			if f.failFirewall {
				return nil, errors.New("firewall query failed")
			}
			for _, record := range f.firewallRules {
				raw, _ := json.Marshal(record)
				resp.Body["FirewallRule"] = append(resp.Body["FirewallRule"], raw)
			}
		}
	}
	return resp, nil
}

func (f *fakeScheduleClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, append([]byte(nil), raw...))
	return &sophos.Response{LoginOK: true}, nil
}

func newScheduleSvc(t *testing.T, schedule map[string]any) (*ScheduleSvc, *fakeScheduleClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	fc := &fakeScheduleClient{schedule: schedule}
	inner := &ObjectSvc{Config: cfg, Creds: store, Catalog: cat, NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc }}
	return &ScheduleSvc{Inner: inner, Audit: NewAuditLog(auditDir, true)}, fc, auditDir
}

func scheduleSvcBody(name string) map[string]any {
	return map[string]any{"Name": name, "Type": "Recurring", "ScheduleDetails": map[string]any{"ScheduleDetail": map[string]any{"Days": "Sunday", "StartTime": "19:45", "StopTime": "23:59"}}}
}

func TestScheduleSvc_CreateDryRunAndNormalizesDetails(t *testing.T) {
	s, fc, _ := newScheduleSvc(t, nil)
	out, err := s.Create(context.Background(), "home", "Night&Shift", scheduleSvcBody("Night&Shift"), true)
	require.NoError(t, err)
	require.NotNil(t, out.Preview)
	require.Equal(t, 1, strings.Count(out.Preview.RedactedXML, "<ScheduleDetail>"))
	require.Empty(t, fc.sent)

	body := scheduleSvcBody("Night&Shift")
	body["ScheduleDetails"] = map[string]any{"ScheduleDetail": []any{
		map[string]any{"Days": "Sunday", "StartTime": "19:45", "StopTime": "23:59"},
		map[string]any{"Days": "Monday", "StartTime": "00:00", "StopTime": "01:00"},
	}}
	_, err = s.Create(context.Background(), "home", "Night&Shift", body, true)
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(fcLastPreview(t, s, body), "<ScheduleDetail>"))
}

func fcLastPreview(t *testing.T, s *ScheduleSvc, body map[string]any) string {
	t.Helper()
	out, err := s.Create(context.Background(), "home", "Night&Shift", body, true)
	require.NoError(t, err)
	return out.Preview.RedactedXML
}

func TestScheduleSvc_CreateValidationBeforeClientAndAudit(t *testing.T) {
	s, fc, auditDir := newScheduleSvc(t, nil)
	body := scheduleSvcBody("bad")
	body["ScheduleDetails"] = map[string]any{"ScheduleDetail": map[string]any{"Days": "Weekend", "StartTime": "10:00", "StopTime": "11:00"}}
	_, err := s.Create(context.Background(), "home", "bad", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Empty(t, fc.tags)
	audit, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(audit), `"result":"error:invalid_request"`)
}

func TestScheduleSvc_ReadOnlyAndHashGates(t *testing.T) {
	live := scheduleSvcBody("Night")
	s, fc, _ := newScheduleSvc(t, live)
	p := s.Inner.Config.Profiles["home"]
	p.ReadOnly = true
	s.Inner.Config.Profiles["home"] = p
	_, err := s.Create(context.Background(), "home", "Night", live, true)
	require.ErrorIs(t, err, sophos.ErrReadOnlyViolation)
	require.Empty(t, fc.sent)
	p.ReadOnly = false
	s.Inner.Config.Profiles["home"] = p
	got, err := s.Inner.Get(context.Background(), "home", "Schedule", "Night")
	require.NoError(t, err)
	liveHash, err := DiffHash(got.Data)
	require.NoError(t, err)
	_, err = s.Update(context.Background(), "home", "Night", live, liveHash, false, true)
	require.NoError(t, err)
	_, err = s.Update(context.Background(), "home", "Night", live, "wrong", false, true)
	require.ErrorIs(t, err, ErrDiffHashMismatch)
	_, err = s.Update(context.Background(), "home", "Night", live, "", false, true)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "expectedDiffHash is required (or set ignoreExpectedDiffHash: true)")
}

func TestScheduleSvc_DeleteReferenceGuardsAndSuccess(t *testing.T) {
	live := scheduleSvcBody("Night&Shift")
	s, fc, auditDir := newScheduleSvc(t, live)
	got, err := s.Inner.Get(context.Background(), "home", "Schedule", "Night&Shift")
	require.NoError(t, err)
	hash, err := DiffHash(got.Data)
	require.NoError(t, err)
	fc.firewallRules = []map[string]any{{"Name": "R1", "Schedule": "Night&Shift"}}
	_, err = s.Delete(context.Background(), "home", "Night&Shift", hash, false, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "referenced by firewall rules: R1")
	require.Empty(t, fc.sent)

	fc.firewallRules = nil
	fc.failFirewall = true
	_, err = s.Delete(context.Background(), "home", "Night&Shift", hash, false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reference scan could not complete")
	fc.failFirewall = false
	fc.firewallRules = []map[string]any{{"Schedule": "Night&Shift"}}
	_, err = s.Delete(context.Background(), "home", "Night&Shift", hash, false, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "could not be examined")

	fc.firewallRules = nil
	out, err := s.Delete(context.Background(), "home", "Night&Shift", hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "delete", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Name>Night&amp;Shift</Name>`)
	audit, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(audit), `"operation":"schedule_delete"`)
	require.Contains(t, string(audit), `"result":"ok"`)
}

func TestScheduleSvc_CreateApplyRefetchFailureAndAuditError(t *testing.T) {
	live := scheduleSvcBody("Night")
	s, fc, _ := newScheduleSvc(t, live)
	fc.failScheduleAfterApply = true
	out, err := s.Create(context.Background(), "home", "Night", live, false)
	require.NoError(t, err)
	require.Empty(t, out.NewDiffHash)
	require.Len(t, fc.sent, 1)
}

func TestScheduleSvc_ShowReferencesPartialAndList(t *testing.T) {
	live := scheduleSvcBody("Night")
	s, fc, _ := newScheduleSvc(t, live)
	fc.firewallRules = []map[string]any{{"Name": "R1", "Schedule": "Night"}}
	show, err := s.Show(context.Background(), "home", "Night", true)
	require.NoError(t, err)
	require.Equal(t, []string{"R1"}, show.References.Refs["FirewallRule"])
	fc.failFirewall = true
	show, err = s.Show(context.Background(), "home", "Night", true)
	require.NoError(t, err)
	require.NotNil(t, show.Object)
	require.NotEmpty(t, show.References.Errors["FirewallRule"])
	fc.tags = nil
	show, err = s.Show(context.Background(), "home", "Night", false)
	require.NoError(t, err)
	require.Nil(t, show.References)
	require.NotContains(t, fc.tags, "FirewallRule")
	list, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, 1, list.Count)
}
