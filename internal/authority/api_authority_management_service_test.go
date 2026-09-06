package authority

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"go.uber.org/zap"
)

// jwtOidcCredentialAttributes builds request attributes for a JWT/OIDC
// authority: just a URL and credential type, matching the fields
// CreateAuthorityInstance actually reads for that credential type.
func jwtOidcCredentialAttributes(url string) []model.Attribute {
	return []model.Attribute{
		model.RequestAttributeDto{
			Uuid:    model.AUTHORITY_URL_ATTR,
			Content: []model.AttributeContent{model.StringAttributeContent{Data: url}},
		},
		model.RequestAttributeDto{
			Uuid:    model.AUTHORITY_CREDENTIAL_TYPE_ATTR,
			Content: []model.AttributeContent{model.StringAttributeContent{Data: model.JWTOIDC_CRED}},
		},
	}
}

func TestGetAuthorityInstanceService(t *testing.T) {
	t.Run("not found returns 404", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.GetAuthorityInstance(context.Background(), "missing-uuid")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusNotFound)
		}
		body, ok := resp.Body.(model.ErrorMessageDto)
		if !ok {
			t.Fatalf("body type = %T, want model.ErrorMessageDto", resp.Body)
		}
		if body.Message != "Authority not found" {
			t.Errorf("message = %q, want %q", body.Message, "Authority not found")
		}
	})

	t.Run("found returns the stored authority", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUID: &db.AuthorityInstance{
			UUID: "authority-uuid", Name: "authority-1", Attributes: "[]",
		}}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.GetAuthorityInstance(context.Background(), "authority-uuid")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
		}
		dto, ok := resp.Body.(model.AuthorityProviderInstanceDto)
		if !ok {
			t.Fatalf("body type = %T, want model.AuthorityProviderInstanceDto", resp.Body)
		}
		if dto.Uuid != "authority-uuid" || dto.Name != "authority-1" {
			t.Errorf("dto = %+v, unexpected", dto)
		}
		if len(repo.findByUUIDCalls) != 1 || repo.findByUUIDCalls[0] != "authority-uuid" {
			t.Errorf("FindAuthorityInstanceByUUID calls = %+v, want one call with %q", repo.findByUUIDCalls, "authority-uuid")
		}
	})
}

func TestListAuthorityInstancesService(t *testing.T) {
	t.Run("maps repository records to DTOs", func(t *testing.T) {
		repo := &fakeAuthorityRepository{list: []*db.AuthorityInstance{
			{UUID: "uuid-1", Name: "authority-1", Attributes: "[]"},
			{UUID: "uuid-2", Name: "authority-2", Attributes: "[]"},
		}}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.ListAuthorityInstances(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
		}
		dtos, ok := resp.Body.([]model.AuthorityProviderInstanceDto)
		if !ok {
			t.Fatalf("body type = %T, want []model.AuthorityProviderInstanceDto", resp.Body)
		}
		if len(dtos) != 2 || dtos[0].Uuid != "uuid-1" || dtos[1].Uuid != "uuid-2" {
			t.Errorf("dtos = %+v, unexpected", dtos)
		}
	})

	// Characterizes existing behavior: ListAuthorityInstances discards the
	// repository's error (`authorities, _ := s.authorityRepo.ListAuthorityInstances()`),
	// so a repository failure is indistinguishable from an empty result.
	t.Run("repository error is silently treated as an empty list", func(t *testing.T) {
		repo := &fakeAuthorityRepository{listErr: errors.New("db unavailable")}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.ListAuthorityInstances(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (the repository error is not surfaced)", resp.Code, http.StatusOK)
		}
		dtos, ok := resp.Body.([]model.AuthorityProviderInstanceDto)
		if !ok {
			t.Fatalf("body type = %T, want []model.AuthorityProviderInstanceDto", resp.Body)
		}
		if len(dtos) != 0 {
			t.Errorf("dtos = %+v, want empty", dtos)
		}
	})
}

func TestRemoveAuthorityInstanceService(t *testing.T) {
	t.Run("not found returns 204", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.RemoveAuthorityInstance(context.Background(), "missing-uuid")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != 204 {
			t.Fatalf("status = %d, want %d", resp.Code, 204)
		}
		if len(repo.deleteCalls) != 0 {
			t.Errorf("DeleteAuthorityInstance should not have been called, got %+v", repo.deleteCalls)
		}
	})

	t.Run("deletes the found authority", func(t *testing.T) {
		authority := &db.AuthorityInstance{UUID: "authority-uuid", Name: "authority-1"}
		repo := &fakeAuthorityRepository{findByUUID: authority}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.RemoveAuthorityInstance(context.Background(), "authority-uuid")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
		}
		if len(repo.deleteCalls) != 1 || repo.deleteCalls[0].UUID != "authority-uuid" {
			t.Fatalf("DeleteAuthorityInstance calls = %+v, want one call for %q", repo.deleteCalls, "authority-uuid")
		}
	})

	t.Run("delete error returns 500", func(t *testing.T) {
		repo := &fakeAuthorityRepository{
			findByUUID: &db.AuthorityInstance{UUID: "authority-uuid"},
			deleteErr:  errors.New("db write failed"),
		}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.RemoveAuthorityInstance(context.Background(), "authority-uuid")

		if err == nil {
			t.Fatal("expected an error")
		}
		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
	})
}

func TestUpdateAuthorityInstanceService(t *testing.T) {
	validAttributes := []model.Attribute{
		model.RequestAttributeDto{
			Uuid:    model.AUTHORITY_URL_ATTR,
			Content: []model.AttributeContent{model.StringAttributeContent{Data: "https://vault.example.com"}},
		},
		model.RequestAttributeDto{
			Uuid:    model.AUTHORITY_CREDENTIAL_TYPE_ATTR,
			Content: []model.AttributeContent{model.StringAttributeContent{Data: model.JWTOIDC_CRED}},
		},
		model.RequestAttributeDto{
			Uuid:    model.AUTHORITY_VAULT_ROLE_ATTR,
			Content: []model.AttributeContent{model.StringAttributeContent{Data: "vault-role"}},
		},
	}

	t.Run("not found returns 500 without updating", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.UpdateAuthorityInstance(context.Background(), "missing-uuid", model.AuthorityProviderInstanceRequestDto{})

		if err == nil {
			t.Fatal("expected an error")
		}
		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
		if len(repo.updateCalls) != 0 {
			t.Errorf("UpdateAuthorityInstance should not have been called, got %+v", repo.updateCalls)
		}
	})

	t.Run("updates the found authority from the request attributes", func(t *testing.T) {
		existing := &db.AuthorityInstance{UUID: "authority-uuid", Name: "old-name"}
		repo := &fakeAuthorityRepository{findByUUID: existing}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.UpdateAuthorityInstance(context.Background(), "authority-uuid", model.AuthorityProviderInstanceRequestDto{
			Name:       "new-name",
			Attributes: validAttributes,
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%+v", resp.Code, http.StatusOK, resp.Body)
		}
		dto, ok := resp.Body.(model.AuthorityProviderInstanceDto)
		if !ok {
			t.Fatalf("body type = %T, want model.AuthorityProviderInstanceDto", resp.Body)
		}
		if dto.Name != "new-name" || dto.Uuid != "authority-uuid" {
			t.Errorf("dto = %+v, unexpected", dto)
		}
		if len(repo.updateCalls) != 1 {
			t.Fatalf("UpdateAuthorityInstance calls = %d, want 1", len(repo.updateCalls))
		}
		updated := repo.updateCalls[0]
		if updated.Name != "new-name" || updated.URL != "https://vault.example.com" ||
			updated.CredentialType != model.JWTOIDC_CRED || updated.VaultRole != "vault-role" {
			t.Errorf("persisted authority = %+v, unexpected", updated)
		}
	})

	t.Run("update error returns 500", func(t *testing.T) {
		repo := &fakeAuthorityRepository{
			findByUUID: &db.AuthorityInstance{UUID: "authority-uuid"},
			updateErr:  errors.New("db write failed"),
		}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.UpdateAuthorityInstance(context.Background(), "authority-uuid", model.AuthorityProviderInstanceRequestDto{
			Attributes: validAttributes,
		})

		if err == nil {
			t.Fatal("expected an error")
		}
		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
	})
}

func TestNewAuthorityManagementAPIService_WiresRepositoryAndLogger(t *testing.T) {
	repo, err := db.NewAuthorityRepository(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	logger := zap.NewNop()

	servicer := NewAuthorityManagementAPIService(repo, logger)

	service, ok := servicer.(*AuthorityManagementAPIService)
	if !ok {
		t.Fatalf("type = %T, want *AuthorityManagementAPIService", servicer)
	}
	if service.authorityRepo != authorityRepository(repo) {
		t.Error("authorityRepo not wired to the repository passed in")
	}
	if service.log != logger {
		t.Error("log not wired to the logger passed in")
	}
}

func TestValidateRAProfileAttributesService_AlwaysReturnsOK(t *testing.T) {
	service := &AuthorityManagementAPIService{log: zap.NewNop()}

	resp, err := service.ValidateRAProfileAttributes(context.Background(), "authority-uuid", []model.RequestAttributeDto{{Name: "x"}})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
	}
}

func TestCreateAuthorityInstanceService_VaultConnectFailureRejectsBeforeCreating(t *testing.T) {
	repo := &fakeAuthorityRepository{}
	service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

	request := model.AuthorityProviderInstanceRequestDto{
		Name:       "authority-1",
		Attributes: jwtOidcCredentialAttributes(unreachableVaultURL),
	}

	resp, err := service.CreateAuthorityInstance(context.Background(), request)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%+v", resp.Code, http.StatusBadRequest, resp.Body)
	}
	body, ok := resp.Body.(model.ErrorMessageDto)
	if !ok {
		t.Fatalf("body type = %T, want model.ErrorMessageDto", resp.Body)
	}
	if body.Message != "Failed to connect to vault" {
		t.Errorf("message = %q, want %q", body.Message, "Failed to connect to vault")
	}
	if len(repo.createCalls) != 0 {
		t.Errorf("CreateAuthorityInstance should not have been reached, got %+v", repo.createCalls)
	}
}

func TestGetConnectionService(t *testing.T) {
	t.Run("not found returns 500", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.GetConnection(context.Background(), "missing-uuid")

		if err == nil {
			t.Fatal("expected an error")
		}
		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
	})

	t.Run("vault connect failure returns 400", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUID: &db.AuthorityInstance{
			UUID: "authority-uuid", URL: unreachableVaultURL, CredentialType: model.JWTOIDC_CRED,
		}}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.GetConnection(context.Background(), "authority-uuid")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body=%+v", resp.Code, http.StatusBadRequest, resp.Body)
		}
		body, ok := resp.Body.(model.ErrorMessageDto)
		if !ok {
			t.Fatalf("body type = %T, want model.ErrorMessageDto", resp.Body)
		}
		if body.Message != "Failed to connect to vault" {
			t.Errorf("message = %q, want %q", body.Message, "Failed to connect to vault")
		}
	})
}

func TestGetCaCertificatesService_AuthorityNotFoundReturns404BeforeReachingVault(t *testing.T) {
	repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
	service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

	resp, err := service.GetCaCertificates(context.Background(), "missing-uuid", model.CaCertificatesRequestDto{
		RaProfileAttributes: []model.Attribute{engineAttribute(map[string]any{"engineName": "pki"})},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNotFound)
	}
}

func TestGetCrlService_AuthorityNotFoundReturns404BeforeReachingVault(t *testing.T) {
	repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
	service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

	resp, err := service.GetCrl(context.Background(), "missing-uuid", model.CertificateRevocationListRequestDto{
		RaProfileAttributes: []model.Attribute{engineAttribute(map[string]any{"engineName": "pki"})},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNotFound)
	}
}

func TestListRAProfileAttributesService(t *testing.T) {
	t.Run("authority not found returns 404", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.ListRAProfileAttributes(context.Background(), "missing-uuid")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusNotFound)
		}
	})

	t.Run("vault connect failure returns 500", func(t *testing.T) {
		repo := &fakeAuthorityRepository{findByUUID: &db.AuthorityInstance{
			UUID: "authority-uuid", URL: unreachableVaultURL, CredentialType: model.JWTOIDC_CRED,
		}}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.ListRAProfileAttributes(context.Background(), "authority-uuid")

		if err == nil {
			t.Fatal("expected an error")
		}
		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
		body, ok := resp.Body.(model.ErrorMessageDto)
		if !ok {
			t.Fatalf("body type = %T, want model.ErrorMessageDto", resp.Body)
		}
		if body.Message != "Failed to create vault client" {
			t.Errorf("message = %q, want %q", body.Message, "Failed to create vault client")
		}
	})
}

func TestRAProfileCallbackService(t *testing.T) {
	t.Run("not found by uuid or name returns 404", func(t *testing.T) {
		repo := &fakeAuthorityRepository{
			findByUUIDErr: errors.New("record not found"),
			findByNameErr: errors.New("record not found"),
		}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.RAProfileCallback(context.Background(), "missing", "pki")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusNotFound)
		}
		if len(repo.findByNameCalls) != 1 || repo.findByNameCalls[0] != "missing" {
			t.Errorf("FindAuthorityInstanceByName calls = %+v, want a fallback lookup for %q", repo.findByNameCalls, "missing")
		}
	})

	t.Run("found by name falls back and reaches vault", func(t *testing.T) {
		repo := &fakeAuthorityRepository{
			findByUUIDErr: errors.New("record not found"),
			findByName: &db.AuthorityInstance{
				UUID: "authority-uuid", Name: "authority-1", URL: unreachableVaultURL, CredentialType: model.JWTOIDC_CRED,
			},
		}
		service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

		resp, err := service.RAProfileCallback(context.Background(), "authority-1", "pki")

		if err == nil {
			t.Fatal("expected an error")
		}
		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
		body, ok := resp.Body.(model.ErrorMessageDto)
		if !ok {
			t.Fatalf("body type = %T, want model.ErrorMessageDto", resp.Body)
		}
		if body.Message != "Failed to create vault client" {
			t.Errorf("message = %q, want %q", body.Message, "Failed to create vault client")
		}
	})
}
