package svc

import "encoding/json"

func jsonUnmarshalImpl(raw []byte, v any) error { return json.Unmarshal(raw, v) }

func jsonMarshalImpl(v any) ([]byte, error) { return json.Marshal(v) }
