package secret

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultPathJoinsPresentSegments(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		prefix, secretPath, secretName string
		want                           string
	}{
		{"all three segments", "team", "db", "password", "team/db/password"},
		{"no prefix", "", "db", "password", "db/password"},
		{"no secret path", "team", "", "password", "team/password"},
		{"name only", "", "", "password", "password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := vaultPath(tc.prefix, tc.secretPath, tc.secretName); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestToJsonWritesStatusAndContentType(t *testing.T) {
	rec := httptest.NewRecorder()

	toJson(t.Context(), rec, http.StatusCreated, map[string]string{"name": "secret"})

	if rec.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content type: got %q, want %q", got, "application/json")
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["name"] != "secret" {
		t.Errorf("name: got %q, want %q", body["name"], "secret")
	}
}

func TestUnmrshlRejectsMalformedBody(t *testing.T) {
	rec := httptest.NewRecorder()
	var target map[string]string

	if unmrshl(rec, []byte("{not json"), &target) {
		t.Fatal("expected unmrshl to report failure for malformed JSON")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestUnmrshlAcceptsWellFormedBody(t *testing.T) {
	rec := httptest.NewRecorder()
	var target map[string]string

	if !unmrshl(rec, []byte(`{"name":"secret"}`), &target) {
		t.Fatal("expected unmrshl to succeed for well-formed JSON")
	}
	if target["name"] != "secret" {
		t.Errorf("name: got %q, want %q", target["name"], "secret")
	}
}
