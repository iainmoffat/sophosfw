package render

import (
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestAuthStatusEnvelope(t *testing.T) {
	got, err := AuthStatusEnvelope(svc.AuthStatus{
		Profile: "home", URL: "https://x", LoggedIn: false, CredentialsBackend: "keychain",
	})
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.authStatus"`)
	require.Contains(t, s, `"profile": "home"`)
	require.Contains(t, s, `"loggedIn": false`)
	require.Contains(t, s, `"credentialsBackend": "keychain"`)
}

func TestProfileListEnvelope(t *testing.T) {
	got, err := ProfileListEnvelope("home", []svc.ProfileInfo{
		{Name: "home", URL: "https://x:4444", ReadOnly: false, Current: true},
	})
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.profileList"`)
	require.Contains(t, s, `"current": "home"`)
	require.Contains(t, s, `"profiles"`)
	require.Contains(t, s, `"name": "home"`)
}

func TestObjectListEnvelope_NoFilter(t *testing.T) {
	out := &svc.ObjectList{
		Profile: "home", Tag: "IPHost", Count: 0, Items: []any{},
	}
	got, err := ObjectListEnvelope(out)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, s, `"xmlTag": "IPHost"`)
	require.Contains(t, s, `"count": 0`)
	require.False(t, strings.Contains(s, `"filter"`), "no filter clause should mean no filter key")
}

func TestHostIPListEnvelope_HasXmlTag(t *testing.T) {
	list := &svc.HostIPList{Profile: "home", Count: 0, Items: []svc.HostIP{}}
	got, err := HostIPListEnvelope("sophosfw.v1.hostIpList", list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.hostIpList"`)
	require.Contains(t, s, `"xmlTag": "IPHost"`)
}

func TestServiceListEnvelope_SearchSchema(t *testing.T) {
	list := &svc.ServiceList{Profile: "home", Count: 0, Items: []svc.Service{}}
	got, err := ServiceListEnvelope("sophosfw.v1.serviceSearch", list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.serviceSearch"`)
	require.Contains(t, s, `"xmlTag": "Services"`)
}

func TestFirewallRuleListEnvelope(t *testing.T) {
	list := &svc.FirewallRuleList{Profile: "home", Count: 0, Items: []map[string]any{}}
	got, err := FirewallRuleListEnvelope(list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.firewallRuleList"`)
	require.Contains(t, s, `"xmlTag": "FirewallRule"`)
}

func TestNATRuleListEnvelope(t *testing.T) {
	list := &svc.NATRuleList{Profile: "home", Count: 0, Items: []map[string]any{}}
	got, err := NATRuleListEnvelope(list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.natRuleList"`)
	require.Contains(t, s, `"xmlTag": "NATRule"`)
}

func TestErrorEnvelope(t *testing.T) {
	got, err := ErrorEnvelope("not_found", "host LAN: not found", "home")
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.error"`)
	require.Contains(t, s, `"kind": "not_found"`)
	require.Contains(t, s, `"profile": "home"`)
}

func TestErrorEnvelope_NoProfile(t *testing.T) {
	got, err := ErrorEnvelope("config_error", "no current profile", "")
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.error"`)
	require.False(t, strings.Contains(s, `"profile"`), "empty profile should be omitted")
}
