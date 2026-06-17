package Cx1ClientGo

import (
	"encoding/json"
	"testing"
)

func TestParseQueryRun_NilValue(t *testing.T) {
	qr, err := parseQueryRun("test-id", nil)
	if err == nil {
		t.Error("expected error for nil value, got nil")
	}
	if len(qr.FailedQueries) != 0 || len(qr.Results) != 0 {
		t.Errorf("expected empty QueryRun, got %+v", qr)
	}
}

func TestParseQueryRun_ErrorReturn(t *testing.T) {
	jsonBody := `{"failed_queries":[{"query_id":"KBZG62TFMN2C2STBOZQS2STBOZQV6SDJM5UF6UTJONVS2UTFMZWGKY3UMVSF6WCTKM======","error":[{"line":1,"startColumn":9,"endColumn":9,"code":"CS1002","message":"; expected"}]}]}`

	var interfaceValue interface{}
	err := json.Unmarshal([]byte(jsonBody), &interfaceValue)
	if err != nil {
		t.Errorf("failed to unmarshal JSON: %v", err)
	}

	qr, err := parseQueryRun("test-id", interfaceValue)
	if err != nil {
		t.Errorf("expected nil for error return, got %v", err)
	}
	t.Logf("parseQueryRun returned error: %v", err)

	if len(qr.FailedQueries) == 0 || len(qr.Results) != 0 {
		t.Errorf("expected QueryRun with FailedQueries and no Results, got %+v", qr)
	}
}

func TestParseQueryRun_ResultsReturn(t *testing.T) {
	jsonBody := `[{"isLeaf":false,"title":"Java","key":"389c6494-c376-4545-9274-ca6f7747e3d0_Java","children":[{"isLeaf":true,"title":"Reflected_XSS (2)","key":"ce8fc29d-ea66-43cb-ace5-de241128567b","data":{"severity":"high"},"children":[]}]}]`

	var interfaceValue interface{}
	err := json.Unmarshal([]byte(jsonBody), &interfaceValue)
	if err != nil {
		t.Errorf("failed to unmarshal JSON: %v", err)
	}

	qr, err := parseQueryRun("test-id", interfaceValue)
	if err != nil {
		t.Errorf("expected nil for error return, got %v", err)
	}
	t.Logf("parseQueryRun returned error: %v", err)

	if len(qr.FailedQueries) != 0 || len(qr.Results) == 0 {
		t.Errorf("expected QueryRun with no FailedQueries and Results, got %+v", qr)
	}
}
