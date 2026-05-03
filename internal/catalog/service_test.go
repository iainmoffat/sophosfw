package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServicesParser_ParsesTCPService(t *testing.T) {
	raw := json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":{"Protocol":"TCP","SourcePort":"1:65535","DestinationPort":"80"}}}`)
	v, err := ServicesParser(raw)
	require.NoError(t, err)
	svc, ok := v.(Service)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "HTTP", svc.Name)
	require.Equal(t, "TCPorUDP", svc.Type)
	require.NotEmpty(t, svc.RawDetails)
}
