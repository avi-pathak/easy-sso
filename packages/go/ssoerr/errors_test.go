package ssoerr

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestStatusCodes(t *testing.T) {
	cases := []struct {
		err  *AuthError
		code Code
		stat int
	}{
		{NewAuthenticationError("", nil), CodeAuthentication, 401},
		{NewMissingTokenError("", nil), CodeMissingToken, 401},
		{NewTokenExpiredError("", nil), CodeTokenExpired, 401},
		{NewAuthorizationError("", nil), CodeAuthorization, 403},
		{NewConfigurationError("", nil), CodeConfiguration, 500},
	}
	for _, tc := range cases {
		if tc.err.Code != tc.code || tc.err.StatusCode != tc.stat {
			t.Errorf("%s: code=%s status=%d", tc.code, tc.err.Code, tc.err.StatusCode)
		}
	}
}

func TestMarshalJSON(t *testing.T) {
	e := NewInvalidAudienceError("bad aud", map[string]any{"expected": []string{"a"}})
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["error"] != "invalid_audience" || got["message"] != "bad aud" {
		t.Fatalf("json = %s", b)
	}
	if got["statusCode"].(float64) != 401 {
		t.Fatalf("statusCode missing: %s", b)
	}
	if _, ok := got["details"]; !ok {
		t.Fatalf("details missing: %s", b)
	}
}

func TestMarshalOmitsEmptyDetails(t *testing.T) {
	b, _ := json.Marshal(NewMissingTokenError("", nil))
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if _, ok := got["details"]; ok {
		t.Fatalf("details should be omitted when nil: %s", b)
	}
}

func TestAsAndCoerce(t *testing.T) {
	orig := NewTokenExpiredError("", nil)
	if ae, ok := As(error(orig)); !ok || ae.Code != CodeTokenExpired {
		t.Fatalf("As failed: %v %v", ae, ok)
	}
	wrapped := Coerce(fmt.Errorf("plain error"))
	if wrapped.Code != CodeAuthentication {
		t.Fatalf("Coerce code = %s", wrapped.Code)
	}
	if same := Coerce(orig); same != orig {
		t.Fatal("Coerce should pass through an existing *AuthError")
	}
}
