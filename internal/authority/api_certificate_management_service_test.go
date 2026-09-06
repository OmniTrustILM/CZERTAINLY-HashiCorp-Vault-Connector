package authority

import (
	"context"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
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
