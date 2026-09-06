package authority

import (
	"context"
	"errors"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"go.uber.org/zap"
	"net/http"
	"testing"
)

func TestAuthorityOperationsRejectInvalidRAProfileEngine(t *testing.T) {
	certificateService := &CertificateManagementAPIService{}
	authorityService := &AuthorityManagementAPIService{}
	invalidAttributes := map[string][]model.Attribute{
		"string data": {
			model.RequestAttributeDto{
				Uuid: model.RA_PROFILE_ENGINE_ATTR,
				Name: "ra_profile_engine",
				Content: []model.AttributeContent{
					model.StringAttributeContent{Data: "pki"},
				},
			},
		},
		"invalid path": {
			model.RequestAttributeDto{
				Uuid: model.RA_PROFILE_ENGINE_ATTR,
				Name: "ra_profile_engine",
				Content: []model.AttributeContent{
					model.ObjectAttributeContent{Data: map[string]any{"engineName": "../pki"}},
				},
			},
		},
	}

	for invalidCase, attributes := range invalidAttributes {
		operations := map[string]func() (model.ImplResponse, error){
			"identify": func() (model.ImplResponse, error) {
				return certificateService.IdentifyCertificate(context.Background(), "authority", model.CertificateIdentificationRequestDto{
					RaProfileAttributes: attributes,
				})
			},
			"issue": func() (model.ImplResponse, error) {
				return certificateService.IssueCertificate(context.Background(), "authority", model.CertificateSignRequestDto{
					CertificateRequestFormat: model.CERTIFICATEREQUESTFORMAT_PKCS10,
					RaProfileAttributes:      attributes,
				})
			},
			"renew": func() (model.ImplResponse, error) {
				return certificateService.RenewCertificate(context.Background(), "authority", model.CertificateRenewRequestDto{
					CertificateRequestFormat: model.CERTIFICATEREQUESTFORMAT_PKCS10,
					RaProfileAttributes:      attributes,
				})
			},
			"revoke": func() (model.ImplResponse, error) {
				return certificateService.RevokeCertificate(context.Background(), "authority", model.CertRevocationDto{
					RaProfileAttributes: attributes,
				})
			},
			"get CA certificates": func() (model.ImplResponse, error) {
				return authorityService.GetCaCertificates(context.Background(), "authority", model.CaCertificatesRequestDto{
					RaProfileAttributes: attributes,
				})
			},
			"get CRL": func() (model.ImplResponse, error) {
				return authorityService.GetCrl(context.Background(), "authority", model.CertificateRevocationListRequestDto{
					RaProfileAttributes: attributes,
				})
			},
		}

		for operationName, operation := range operations {
			t.Run(invalidCase+"/"+operationName, func(t *testing.T) {
				response, err := operation()
				if err != nil {
					t.Fatalf("operation returned error: %v", err)
				}
				if response.Code != http.StatusBadRequest {
					t.Fatalf("response code = %d, want %d", response.Code, http.StatusBadRequest)
				}
				errorResponse, ok := response.Body.(model.ErrorMessageDto)
				if !ok {
					t.Fatalf("response body type = %T, want model.ErrorMessageDto", response.Body)
				}
				if errorResponse.Message != "Invalid RA profile engine attribute" {
					t.Fatalf("response message = %q", errorResponse.Message)
				}
			})
		}
	}
}

func TestRAProfileCallbackRejectsInvalidEnginePath(t *testing.T) {
	service := &AuthorityManagementAPIService{}

	response, err := service.RAProfileCallback(context.Background(), "authority", "../pki")
	if err != nil {
		t.Fatalf("callback returned error: %v", err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response code = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestSigningOperationsRejectNonPKCS10Format(t *testing.T) {
	service := &CertificateManagementAPIService{}
	operations := map[string]func() (model.ImplResponse, error){
		"issue": func() (model.ImplResponse, error) {
			return service.IssueCertificate(context.Background(), "authority", model.CertificateSignRequestDto{
				CertificateRequestFormat: "",
			})
		},
		"renew": func() (model.ImplResponse, error) {
			return service.RenewCertificate(context.Background(), "authority", model.CertificateRenewRequestDto{
				CertificateRequestFormat: "",
			})
		},
	}

	for operationName, operation := range operations {
		t.Run(operationName, func(t *testing.T) {
			response, err := operation()
			if err != nil {
				t.Fatalf("operation returned error: %v", err)
			}
			if response.Code != http.StatusBadRequest {
				t.Fatalf("response code = %d, want %d", response.Code, http.StatusBadRequest)
			}
			errorResponse, ok := response.Body.(model.ErrorMessageDto)
			if !ok {
				t.Fatalf("response body type = %T, want model.ErrorMessageDto", response.Body)
			}
			want := "Invalid certificate request format, PKCS#10 format expected."
			if errorResponse.Message != want {
				t.Fatalf("response message = %q, want %q", errorResponse.Message, want)
			}
		})
	}
}

func TestSigningOperationsRejectInvalidRAProfileRole(t *testing.T) {
	service := &CertificateManagementAPIService{}
	invalidRoles := map[string]model.AttributeContent{
		"object data":  model.ObjectAttributeContent{Data: map[string]any{"role": "server"}},
		"invalid path": model.StringAttributeContent{Data: "../server"},
	}

	for invalidCase, roleContent := range invalidRoles {
		attributes := []model.Attribute{
			engineAttribute(map[string]any{"engineName": "pki"}),
			model.RequestAttributeDto{
				Uuid:    model.RA_PROFILE_ROLE_ATTR,
				Name:    "ra_profile_role",
				Content: []model.AttributeContent{roleContent},
			},
		}
		operations := map[string]func() (model.ImplResponse, error){
			"issue": func() (model.ImplResponse, error) {
				return service.IssueCertificate(context.Background(), "authority", model.CertificateSignRequestDto{
					CertificateRequestFormat: model.CERTIFICATEREQUESTFORMAT_PKCS10,
					RaProfileAttributes:      attributes,
				})
			},
			"renew": func() (model.ImplResponse, error) {
				return service.RenewCertificate(context.Background(), "authority", model.CertificateRenewRequestDto{
					CertificateRequestFormat: model.CERTIFICATEREQUESTFORMAT_PKCS10,
					RaProfileAttributes:      attributes,
				})
			},
		}

		for operationName, operation := range operations {
			t.Run(invalidCase+"/"+operationName, func(t *testing.T) {
				response, err := operation()
				if err != nil {
					t.Fatalf("operation returned error: %v", err)
				}
				if response.Code != http.StatusBadRequest {
					t.Fatalf("response code = %d, want %d", response.Code, http.StatusBadRequest)
				}
			})
		}
	}
}

func TestGetRAProfileEngineName(t *testing.T) {
	tests := []struct {
		name       string
		attributes []model.Attribute
		want       string
		wantErr    bool
	}{
		{name: "missing attribute", wantErr: true},
		{
			name: "missing content",
			attributes: []model.Attribute{
				model.RequestAttributeDto{Uuid: model.RA_PROFILE_ENGINE_ATTR},
			},
			wantErr: true,
		},
		{
			name: "missing engine name",
			attributes: []model.Attribute{
				engineAttribute(map[string]any{"accessor": "accessor"}),
			},
			wantErr: true,
		},
		{
			name: "non-string engine name",
			attributes: []model.Attribute{
				engineAttribute(map[string]any{"engineName": 123}),
			},
			wantErr: true,
		},
		{
			name: "nested mount path",
			attributes: []model.Attribute{
				engineAttribute(map[string]any{"engineName": "team/pki-root"}),
			},
			want: "team/pki-root",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := getRAProfileEngineName(test.attributes)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("get engine name: %v", err)
			}
			if got != test.want {
				t.Fatalf("engine name = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGetRAProfileRoleName(t *testing.T) {
	tests := []struct {
		name       string
		attributes []model.Attribute
		want       string
		wantErr    bool
	}{
		{name: "missing attribute", wantErr: true},
		{
			name: "missing content",
			attributes: []model.Attribute{
				model.RequestAttributeDto{Uuid: model.RA_PROFILE_ROLE_ATTR},
			},
			wantErr: true,
		},
		{
			name: "valid role",
			attributes: []model.Attribute{
				model.RequestAttributeDto{
					Uuid: model.RA_PROFILE_ROLE_ATTR,
					Content: []model.AttributeContent{
						model.StringAttributeContent{Data: "server-role"},
					},
				},
			},
			want: "server-role",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := getRAProfileRoleName(test.attributes)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("get role name: %v", err)
			}
			if got != test.want {
				t.Fatalf("role name = %q, want %q", got, test.want)
			}
		})
	}
}

func TestValidVaultMountPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "pki", want: true},
		{path: "team/pki-root", want: true},
		{path: ""},
		{path: " pki"},
		{path: "pki/"},
		{path: "/pki"},
		{path: "pki//root"},
		{path: "pki/../root"},
		{path: "pki..root"},
		{path: `pki\root`},
		{path: "pki?namespace=root"},
		{path: "pki%2Froot"},
		{path: "pki\nroot"},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := isValidVaultMountPath(test.path); got != test.want {
				t.Fatalf("isValidVaultMountPath(%q) = %t, want %t", test.path, got, test.want)
			}
		})
	}
}

func TestValidVaultPathSegment(t *testing.T) {
	tests := []struct {
		segment string
		want    bool
	}{
		{segment: "server-role", want: true},
		{segment: "role_1.v2", want: true},
		{segment: "foo/bar"},
		{segment: "team/pki-root"},
		{segment: ""},
		{segment: "../server"},
		{segment: " role"},
	}

	for _, test := range tests {
		t.Run(test.segment, func(t *testing.T) {
			if got := isValidVaultPathSegment(test.segment); got != test.want {
				t.Fatalf("isValidVaultPathSegment(%q) = %t, want %t", test.segment, got, test.want)
			}
		})
	}
}

func engineAttribute(data map[string]any) model.RequestAttributeDto {
	return model.RequestAttributeDto{
		Uuid: model.RA_PROFILE_ENGINE_ATTR,
		Name: "ra_profile_engine",
		Content: []model.AttributeContent{
			model.ObjectAttributeContent{Data: data},
		},
	}
}

func roleAttribute(name string) model.RequestAttributeDto {
	return model.RequestAttributeDto{
		Uuid: model.RA_PROFILE_ROLE_ATTR,
		Name: "ra_profile_role",
		Content: []model.AttributeContent{
			model.StringAttributeContent{Data: name},
		},
	}
}

func TestNewCertificateManagementAPIService_WiresRepositoryAndLogger(t *testing.T) {
	repo, err := db.NewAuthorityRepository(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	logger := zap.NewNop()

	servicer := NewCertificateManagementAPIService(repo, logger)

	service, ok := servicer.(*CertificateManagementAPIService)
	if !ok {
		t.Fatalf("type = %T, want *CertificateManagementAPIService", servicer)
	}
	if service.authorityRepo != authorityRepository(repo) {
		t.Error("authorityRepo not wired to the repository passed in")
	}
	if service.log != logger {
		t.Error("log not wired to the logger passed in")
	}
}

func TestCertificateManagementServiceNoOpEndpoints_AlwaysReturnOK(t *testing.T) {
	service := &CertificateManagementAPIService{log: zap.NewNop()}
	operations := map[string]func() (model.ImplResponse, error){
		"list issue attributes": func() (model.ImplResponse, error) {
			return service.ListIssueCertificateAttributes(context.Background(), "authority-uuid")
		},
		"list revoke attributes": func() (model.ImplResponse, error) {
			return service.ListRevokeCertificateAttributes(context.Background(), "authority-uuid")
		},
		"validate issue attributes": func() (model.ImplResponse, error) {
			return service.ValidateIssueCertificateAttributes(context.Background(), "authority-uuid", []model.RequestAttributeDto{{Name: "x"}})
		},
		"validate revoke attributes": func() (model.ImplResponse, error) {
			return service.ValidateRevokeCertificateAttributes(context.Background(), "authority-uuid", []model.RequestAttributeDto{{Name: "x"}})
		},
	}

	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			resp, err := operation()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
			}
		})
	}
}

// certificateOperations returns, for each certificate-management operation
// that looks up an authority before touching Vault, a closure invoking that
// operation against service with RA profile attributes sufficient to pass
// the engine/role resolution and reach findAuthority.
func certificateOperations(service *CertificateManagementAPIService, uuid string) map[string]func() (model.ImplResponse, error) {
	engineOnly := []model.Attribute{engineAttribute(map[string]any{"engineName": "pki"})}
	engineAndRole := []model.Attribute{
		engineAttribute(map[string]any{"engineName": "pki"}),
		roleAttribute("server-role"),
	}
	return map[string]func() (model.ImplResponse, error){
		"identify": func() (model.ImplResponse, error) {
			return service.IdentifyCertificate(context.Background(), uuid, model.CertificateIdentificationRequestDto{
				RaProfileAttributes: engineOnly,
			})
		},
		"issue": func() (model.ImplResponse, error) {
			return service.IssueCertificate(context.Background(), uuid, model.CertificateSignRequestDto{
				CertificateRequestFormat: model.CERTIFICATEREQUESTFORMAT_PKCS10,
				RaProfileAttributes:      engineAndRole,
			})
		},
		"renew": func() (model.ImplResponse, error) {
			return service.RenewCertificate(context.Background(), uuid, model.CertificateRenewRequestDto{
				CertificateRequestFormat: model.CERTIFICATEREQUESTFORMAT_PKCS10,
				RaProfileAttributes:      engineAndRole,
			})
		},
		"revoke": func() (model.ImplResponse, error) {
			return service.RevokeCertificate(context.Background(), uuid, model.CertRevocationDto{
				RaProfileAttributes: engineOnly,
			})
		},
	}
}

func TestCertificateOperationsService_AuthorityNotFoundReturns404BeforeReachingVault(t *testing.T) {
	repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("record not found")}
	service := &CertificateManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

	for name, operation := range certificateOperations(service, "missing-uuid") {
		t.Run(name, func(t *testing.T) {
			resp, err := operation()
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
	}
}

func TestCertificateOperationsService_VaultConnectFailureReturns500(t *testing.T) {
	repo := &fakeAuthorityRepository{findByUUID: &db.AuthorityInstance{
		UUID: "authority-uuid", URL: unreachableVaultURL, CredentialType: model.JWTOIDC_CRED,
	}}
	service := &CertificateManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

	for name, operation := range certificateOperations(service, "authority-uuid") {
		t.Run(name, func(t *testing.T) {
			resp, err := operation()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d; body=%+v", resp.Code, http.StatusInternalServerError, resp.Body)
			}
			if _, ok := resp.Body.(model.ErrorMessageDto); !ok {
				t.Fatalf("body type = %T, want model.ErrorMessageDto", resp.Body)
			}
		})
	}
}
