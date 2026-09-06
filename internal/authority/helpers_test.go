package authority

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/utils"
)

func TestResolveEngineName(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		attributes := []model.Attribute{engineAttribute(map[string]any{"engineName": "pki"})}

		got, errResp := resolveEngineName(attributes)

		if errResp != nil {
			t.Fatalf("unexpected error response: %+v", *errResp)
		}
		if got != "pki" {
			t.Errorf("engine name = %q, want %q", got, "pki")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		got, errResp := resolveEngineName(nil)

		if got != "" {
			t.Errorf("engine name = %q, want empty", got)
		}
		if errResp == nil {
			t.Fatal("expected an error response")
		}
		if errResp.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want %d", errResp.Code, http.StatusBadRequest)
		}
		body, ok := errResp.Body.(model.ErrorMessageDto)
		if !ok {
			t.Fatalf("body type = %T, want model.ErrorMessageDto", errResp.Body)
		}
		if body.Message != invalidRAProfileEngineMessage {
			t.Errorf("message = %q, want %q", body.Message, invalidRAProfileEngineMessage)
		}
	})
}

func TestResolveRoleName(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		attributes := []model.Attribute{
			model.RequestAttributeDto{
				Uuid:    model.RA_PROFILE_ROLE_ATTR,
				Content: []model.AttributeContent{model.StringAttributeContent{Data: "server-role"}},
			},
		}

		got, errResp := resolveRoleName(attributes)

		if errResp != nil {
			t.Fatalf("unexpected error response: %+v", *errResp)
		}
		if got != "server-role" {
			t.Errorf("role name = %q, want %q", got, "server-role")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		got, errResp := resolveRoleName(nil)

		if got != "" {
			t.Errorf("role name = %q, want empty", got)
		}
		if errResp == nil {
			t.Fatal("expected an error response")
		}
		if errResp.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want %d", errResp.Code, http.StatusBadRequest)
		}
		body, ok := errResp.Body.(model.ErrorMessageDto)
		if !ok {
			t.Fatalf("body type = %T, want model.ErrorMessageDto", errResp.Body)
		}
		if body.Message != invalidRAProfileRoleMessage {
			t.Errorf("message = %q, want %q", body.Message, invalidRAProfileRoleMessage)
		}
	})
}

func TestCertificateChainResponse(t *testing.T) {
	chain := []string{"cert-a", "cert-b"}

	got := certificateChainResponse(chain)

	if len(got.Certificates) != len(chain) {
		t.Fatalf("got %d certificates, want %d", len(got.Certificates), len(chain))
	}
	wantUuid := utils.DeterministicGUID()
	for i, cert := range got.Certificates {
		if cert.CertificateData != chain[i] {
			t.Errorf("certificate %d data = %q, want %q", i, cert.CertificateData, chain[i])
		}
		if cert.CertificateType != "X.509" {
			t.Errorf("certificate %d type = %q, want %q", i, cert.CertificateType, "X.509")
		}
		if cert.Uuid != wantUuid {
			t.Errorf("certificate %d uuid = %q, want %q", i, cert.Uuid, wantUuid)
		}
		if cert.Meta != nil {
			t.Errorf("certificate %d meta = %v, want nil", i, cert.Meta)
		}
	}
}

func TestCertificateChainResponseEmptyChain(t *testing.T) {
	got := certificateChainResponse(nil)

	if len(got.Certificates) != 0 {
		t.Fatalf("got %d certificates, want 0", len(got.Certificates))
	}
}

func TestOptionalStringAttribute(t *testing.T) {
	attributes := []model.Attribute{
		model.RequestAttributeDto{
			Uuid:    model.AUTHORITY_MOUNT_PATH_ATTR,
			Content: []model.AttributeContent{model.StringAttributeContent{Data: "team/pki"}},
		},
	}

	if got := optionalStringAttribute(model.AUTHORITY_MOUNT_PATH_ATTR, attributes); got != "team/pki" {
		t.Errorf("present attribute: got %q, want %q", got, "team/pki")
	}
	if got := optionalStringAttribute(model.AUTHORITY_VAULT_ROLE_ATTR, attributes); got != "" {
		t.Errorf("absent attribute: got %q, want empty", got)
	}
}

func TestSecretAttributeValue(t *testing.T) {
	attributes := []model.Attribute{
		model.RequestAttributeDto{
			Uuid: model.AUTHORITY_ROLE_ID_ATTR,
			Content: []model.AttributeContent{
				model.SecretAttributeContent{Data: model.SecretAttributeContentData{Secret: "role-id-value"}},
			},
		},
	}

	if got := secretAttributeValue(model.AUTHORITY_ROLE_ID_ATTR, attributes); got != "role-id-value" {
		t.Errorf("got %q, want %q", got, "role-id-value")
	}
}

func TestMarshalAttributes(t *testing.T) {
	attributes := []model.Attribute{
		model.RequestAttributeDto{Uuid: "some-uuid", Name: "some-name", Content: []model.AttributeContent{}},
	}

	got, errResp, err := marshalAttributes(attributes)

	if errResp != nil {
		t.Fatalf("unexpected error response: %+v", *errResp)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, err := json.Marshal(attributes)
	if err != nil {
		t.Fatalf("reference marshal failed: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %s, want %s", got, want)
	}
}
