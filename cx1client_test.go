package Cx1ClientGo

import "testing"

func TestValueOrEnv(t *testing.T) {
	t.Setenv("CX1_TEST_VAR", "  from-env \n")

	if got := valueOrEnv("from-flag", "CX1_TEST_VAR"); got != "from-flag" {
		t.Errorf("flag value must take precedence, got %q", got)
	}
	if got := valueOrEnv("", "CX1_TEST_VAR"); got != "from-env" {
		t.Errorf("expected trimmed env value, got %q", got)
	}
	if got := valueOrEnv("", "CX1_TEST_UNSET_VAR"); got != "" {
		t.Errorf("expected empty for unset env var, got %q", got)
	}
}
