package svc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditLog_AppendsLine(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, true)
	require.NoError(t, a.Write(AuditEntry{
		Profile:    "home",
		Operation:  "create",
		ObjectType: "IPHost",
		ObjectName: "LAN-network",
		Result:     "ok",
	}))
	body, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(string(body), "\n"))
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	require.Len(t, lines, 1)
	var got AuditEntry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &got))
	require.Equal(t, "home", got.Profile)
	require.Equal(t, "create", got.Operation)
	require.Equal(t, "IPHost", got.ObjectType)
	require.Equal(t, "LAN-network", got.ObjectName)
	require.Equal(t, "ok", got.Result)
	require.NotEmpty(t, got.Timestamp)
}

func TestAuditLog_Disabled(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, false)
	require.NoError(t, a.Write(AuditEntry{Profile: "home", Operation: "create"}))
	_, err := os.Stat(filepath.Join(dir, "audit.log"))
	require.True(t, os.IsNotExist(err), "audit.log must not be created when disabled")
}

func TestAuditLog_FileMode(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, true)
	require.NoError(t, a.Write(AuditEntry{Profile: "home", Operation: "create"}))
	info, err := os.Stat(filepath.Join(dir, "audit.log"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestAuditLog_Concurrent(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, true)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Write(AuditEntry{Profile: "home", Operation: "create"})
		}()
	}
	wg.Wait()
	body, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	require.Len(t, lines, 100)
}
