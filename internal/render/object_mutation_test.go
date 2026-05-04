package render

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

func TestObjectMutationEnvelope_DryRun(t *testing.T) {
	r := &svc.ObjectMutationResult{
		Profile:    "home",
		ObjectType: "IPHostGroup",
		Name:       "g1",
		Operation:  "create",
		DryRun:     true,
		Preview:    &svc.Preview{Profile: "home", Mutating: true, RedactedXML: "<Set ...>"},
	}
	b, err := ObjectMutationEnvelope(r)
	require.NoError(t, err)
	var env map[string]any
	require.NoError(t, json.Unmarshal(b, &env))
	require.Equal(t, "sophosfw.v1.ipHostGroupMutation", env["schema"])
	require.Equal(t, false, env["applied"])
	require.NotNil(t, env["preview"])
}

func TestObjectMutationEnvelope_Apply(t *testing.T) {
	r := &svc.ObjectMutationResult{
		Profile:     "home",
		ObjectType:  "Services",
		Name:        "ssh",
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: "abc",
		Item:        map[string]any{"Name": "ssh"},
	}
	b, err := ObjectMutationEnvelope(r)
	require.NoError(t, err)
	var env map[string]any
	require.NoError(t, json.Unmarshal(b, &env))
	require.Equal(t, "sophosfw.v1.servicesMutation", env["schema"])
	require.Equal(t, true, env["applied"])
	require.Equal(t, "abc", env["newDiffHash"])
	require.NotNil(t, env["item"])
}

func TestObjectMutationEnvelope_UnknownType_FallbackSchema(t *testing.T) {
	r := &svc.ObjectMutationResult{Profile: "home", ObjectType: "Mystery", Name: "x", Operation: "create", DryRun: false}
	b, err := ObjectMutationEnvelope(r)
	require.NoError(t, err)
	var env map[string]any
	require.NoError(t, json.Unmarshal(b, &env))
	require.Equal(t, "sophosfw.v1.objectMutation", env["schema"])
}
