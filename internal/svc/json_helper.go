package svc

import "encoding/json"

func jsonUnmarshalImpl(raw []byte, v any) error { return json.Unmarshal(raw, v) }
