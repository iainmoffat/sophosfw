package svc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// fakeRefClient returns canned responses keyed by the GetOp's XMLTag.
// errs[tag] makes that tag's lookup fail.
type fakeRefClient struct {
	body map[string][]json.RawMessage
	errs map[string]error
}

func (f fakeRefClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	if len(env.Operations) == 0 {
		return &sophos.Response{LoginOK: true}, nil
	}
	op, ok := env.Operations[0].(sophos.GetOp)
	if !ok {
		return &sophos.Response{LoginOK: true}, nil
	}
	if e := f.errs[op.XMLTag]; e != nil {
		return nil, e
	}
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if recs, ok := f.body[op.XMLTag]; ok {
		resp.Body[op.XMLTag] = recs
	}
	return resp, nil
}
func (fakeRefClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRefSvc(t *testing.T, body map[string][]json.RawMessage, errs map[string]error) *ObjectSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return &ObjectSvc{
		Config:    cfg,
		Creds:     store,
		Catalog:   cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeRefClient{body: body, errs: errs} },
	}
}

func TestFindReferences_AllSucceed(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"LAN-group","HostList":["LAN-network","LAN-DHCP"]}`)},
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN-network"],"Action":"Accept"}`),
			json.RawMessage(`{"Name":"DMZ-To-WAN","Sources":["DMZ-network"],"Action":"Accept"}`),
		},
		"NATRule": {},
	}
	svc := newRefSvc(t, body, nil)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, []string{"LAN-group"}, got.Refs["IPHostGroup"])
	require.Equal(t, []string{"LAN-To-WAN"}, got.Refs["FirewallRule"])
	require.Equal(t, []string{}, got.Refs["NATRule"])
	require.Empty(t, got.Errors)
}

func TestFindReferences_OneReferrerFails(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"LAN-group","HostList":["LAN-network"]}`)},
		"NATRule":     {},
	}
	errs := map[string]error{"FirewallRule": sophos.ErrPermissionDenied}
	svc := newRefSvc(t, body, errs)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, []string{"LAN-group"}, got.Refs["IPHostGroup"])
	require.Equal(t, []string{}, got.Refs["NATRule"])
	require.Contains(t, got.Errors["FirewallRule"], "permission")
}

func TestFindReferences_PrimaryNotInMap(t *testing.T) {
	svc := newRefSvc(t, nil, nil)
	_, err := FindReferences(context.Background(), svc, "home", "Interface", "eth0")
	require.Error(t, err)
}

func TestFindReferences_ExactMatchOnly(t *testing.T) {
	// "LAN-network-extra" must NOT match a query for "LAN-network".
	body := map[string][]json.RawMessage{
		"IPHostGroup":  {json.RawMessage(`{"Name":"LAN-extra-group","HostList":["LAN-network-extra"]}`)},
		"FirewallRule": {},
		"NATRule":      {},
	}
	svc := newRefSvc(t, body, nil)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Empty(t, got.Refs["IPHostGroup"])
}

// A host buried in the middle of a large group must still be found. Under the
// truncating decoder only the last member of a group survived the read, so a
// reference scan reported "no references" for every other member — which reads
// as "safe to delete" for a host that is in fact in use.
//
// The group here deliberately holds several members and the target is NOT the
// last one: a single-member fixture, or one whose target happens to be last,
// passes under both the broken and the fixed decoder.
func TestFindReferences_FindsMemberInMiddleOfGroup(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"big-group","HostList":{"Host":[` +
			`"alpha","bravo","LAN-network","charlie","delta"]}}`)},
		"FirewallRule": {},
		"NATRule":      {},
	}
	svc := newRefSvc(t, body, nil)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, []string{"big-group"}, got.Refs["IPHostGroup"],
		"a mid-list group member must be reported as referenced")
}

func TestFindReferences_ScheduleUsesKeyScopedMatching(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"scheduled","NetworkPolicy":{"Schedule":"NightShift"}}`),
			json.RawMessage(`{"Name":"description-collision","Description":"NightShift","Schedule":"Other"}`),
			json.RawMessage(`{"Name":"array-value","Schedule":["NightShift"]}`),
		},
	}
	svc := newRefSvc(t, body, nil)

	got, err := FindReferences(context.Background(), svc, "home", "Schedule", "NightShift")
	require.NoError(t, err)
	require.Equal(t, []string{"scheduled"}, got.Refs["FirewallRule"])

	got, err = FindReferences(context.Background(), svc, "home", "IPHost", "NightShift")
	require.NoError(t, err)
	require.Contains(t, got.Refs["FirewallRule"], "description-collision",
		"other primaries retain any-leaf matching")
}

func TestFindReferences_SkippedMatchingNamelessRecord(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Schedule":"NightShift"}`),
			json.RawMessage(`{"Description":"NightShift"}`),
		},
	}
	svc := newRefSvc(t, body, nil)

	got, err := FindReferences(context.Background(), svc, "home", "Schedule", "NightShift")
	require.NoError(t, err)
	require.Empty(t, got.Refs["FirewallRule"])
	require.Equal(t, map[string]int{"FirewallRule": 1}, skippedCounts(t, got))
}

func TestFindReferences_SkippedMatchingEmptyNameRecord(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"","Schedule":"NightShift"}`),
		},
	}
	svc := newRefSvc(t, body, nil)

	got, err := FindReferences(context.Background(), svc, "home", "Schedule", "NightShift")
	require.NoError(t, err)
	require.Empty(t, got.Refs["FirewallRule"])
	require.Equal(t, map[string]int{"FirewallRule": 1}, skippedCounts(t, got))
}

func TestFindReferences_NonmatchingNamelessRecordIsNotSkipped(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {json.RawMessage(`{"Schedule":"Other"}`)},
	}
	svc := newRefSvc(t, body, nil)

	got, err := FindReferences(context.Background(), svc, "home", "Schedule", "NightShift")
	require.NoError(t, err)
	require.Nil(t, skippedCounts(t, got))
}

func TestFindReferences_ReferrerListErrorKeepsEmptyRefsAndError(t *testing.T) {
	svc := newRefSvc(t, nil, map[string]error{"FirewallRule": sophos.ErrPermissionDenied})

	got, err := FindReferences(context.Background(), svc, "home", "Schedule", "NightShift")
	require.NoError(t, err)
	require.Equal(t, []string{}, got.Refs["FirewallRule"])
	require.Contains(t, got.Errors["FirewallRule"], "permission")
}

func TestRecordContainsUnderKey_DoesNotMatchArrayValue(t *testing.T) {
	var record map[string]any
	require.NoError(t, json.Unmarshal(json.RawMessage(`{"Schedule":["X"]}`), &record))

	require.False(t, recordContainsUnderKey(record, "Schedule", "X"))
}

func skippedCounts(t *testing.T, refs *References) map[string]int {
	t.Helper()
	b, err := json.Marshal(refs)
	require.NoError(t, err)
	var rendered struct {
		Skipped map[string]int `json:"skipped"`
	}
	require.NoError(t, json.Unmarshal(b, &rendered))
	return rendered.Skipped
}
