package secret

import (
	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"
)

// Secret attributes definitions
var (
	secretManagementInfo = sm.InfoAttributeV3{
		Uuid:          "4f024397-aa6a-4307-9e3b-7ffdbd0afb6f",
		Version:       ptr(int32(3)),
		SchemaVersion: sm.V3,
		Name:          "info_secret_management_explanation",
		Description:   ptr("Secret operations related information"),
		ContentType:   sm.AttributeContentTypeText,
		Properties: sm.InfoAttributeProperties{
			Label:   "Secret operations related information",
			Visible: true,
		},
	}
	secretManagementPath = sm.DataAttributeV3{
		Uuid:          "17e54346-3c10-4afe-b221-b4e0325c306d",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_secret_management_secret_path",
		Type:          sm.Data,
		ContentType:   sm.AttributeContentTypeString,
		Description:   ptr("Relative path of secret in Vault without trailing slash."),
		Properties: sm.DataAttributeProperties{
			Label:    "Relative secret path",
			Visible:  true,
			Required: false,
		},
	}
)

// Vault Profile attributes definitions
var (
	vaultManagementProfileInfo = sm.InfoAttributeV3{
		Uuid:          "f2f17379-438f-4457-b322-5c4db383f206",
		Version:       ptr(int32(3)),
		SchemaVersion: sm.V3,
		Name:          "info_vault_management_profile_explanation",
		Description:   ptr("Create a new HashiCorp Vault profile configuration"),
		ContentType:   sm.AttributeContentTypeText,
		Properties: sm.InfoAttributeProperties{
			Label:   "HashiCorp Vault profile configuration",
			Visible: true,
		},
	}
	vaultManagementProfileMount = sm.DataAttributeV3{
		Uuid:          "11541b02-6752-4651-8df3-86bed296af78",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_vault_management_profile_mount",
		ContentType:   sm.AttributeContentTypeString,
		Description:   ptr("Vault mount point"),
		Properties: sm.DataAttributeProperties{
			Label:    "Vault mount point",
			Visible:  true,
			Required: true,
			List:     true,
		},
	}
	vaultManagementProfilePath = sm.DataAttributeV3{
		Uuid:          "19c0493b-1eb3-4d20-9394-610f63078109",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_vault_management_profile_secret_path_prefix",
		Type:          sm.Data,
		ContentType:   sm.AttributeContentTypeString,
		Description:   ptr("Secret path prefix in Vault without trailing slash"),
		Properties: sm.DataAttributeProperties{
			Label:    "Secret path prefix",
			Visible:  true,
			Required: false,
		},
	}
)

// Vault instance attributes definitions
var (
	vaultManagementInfo = sm.InfoAttributeV3{
		Uuid:          "890470a6-8cdd-4af9-a344-4f409dda4a64",
		Version:       ptr(int32(3)),
		SchemaVersion: sm.V3,
		Name:          "info_vault_management_explanation",
		Description:   ptr("Create a new HashiCorp Vault instance configuration"),
		ContentType:   sm.AttributeContentTypeText,
		Properties: sm.InfoAttributeProperties{
			Label:   "HashiCorp Vault instance configuration",
			Visible: true,
		},
	}
	vaultManagementURI = sm.DataAttributeV3{
		Uuid:          "ffd606d5-5fd0-4425-9a5a-29c2713ce18d",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_vault_management_uri",
		ContentType:   sm.AttributeContentTypeString,
		Description:   ptr("Vault URL should be in the following format: `http(s)://<vault-url>:<port>`."),
		Properties: sm.DataAttributeProperties{
			Label:    "Vault URL",
			Visible:  true,
			Required: true,
		},
	}
	vaultManagementCredentialType = sm.DataAttributeV3{
		Uuid:          "f461a9ab-7a99-4b41-b190-d0338e833064",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_vault_management_credential_type",
		ContentType:   sm.AttributeContentTypeString,
		Description:   ptr("List of available Vault authentication methods"),
		Properties: sm.DataAttributeProperties{
			Label:       "Please select an authentication method",
			Visible:     true,
			Required:    true,
			ReadOnly:    false,
			List:        true,
			MultiSelect: false,
		},
	}
	vaultManagementNamespace = sm.DataAttributeV3{
		Uuid:          "b7755e40-3ad3-404b-af8d-55a8a1105213",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_vault_management_namespace",
		ContentType:   sm.AttributeContentTypeString,
		Description:   ptr("Vault namespace the request is taking place within"),
		Properties: sm.DataAttributeProperties{
			Label:    "Vault namespace",
			Visible:  true,
			Required: false,
		},
	}
)

// credential type specific attribute definitions
var (
	credentialTypeAppRole = sm.StringAttributeContentV3{
		Reference: ptr("AppRole"),
		Data:      "approle",
	}
	credentialTypeJwt = sm.StringAttributeContentV3{
		Reference: ptr("JWT/OIDC"),
		Data:      "jwt",
	}
	credentialTypeK8s = sm.StringAttributeContentV3{
		Reference: ptr("Kubernetes"),
		Data:      "kubernetes",
	}
	vaultManagementRoleID = sm.DataAttributeV3{
		Version:     3,
		Uuid:        "302af8ad-0c4d-4eb2-9add-2d4a894c6b32",
		Name:        "data_vault_management_role_id",
		Description: ptr("Vault AppRole ID."),
		ContentType: sm.AttributeContentTypeResource,
		Properties: sm.DataAttributeProperties{
			Resource: ptr(sm.Secrets),
			Visible:  true,
			Label:    "AppRole ID",
			Required: true,
		},
		AttributeCallback: &sm.AttributeCallback{
			Mappings: []sm.AttributeCallbackMapping{
				{
					To:      "SECRET_TYPE.EQUALS",
					Targets: []sm.AttributeValueTarget{sm.Filter},
					Value:   []sm.SecretType{sm.Generic, sm.ApiKey},
				},
			},
		},
		SchemaVersion: sm.V3,
	}
	vaultManagementRoleSecret = sm.DataAttributeV3{
		Uuid:          "f8ee975c-aad5-4b48-bac9-46daa1a9a689",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_vault_management_role_secret",
		ContentType:   sm.AttributeContentTypeResource,
		Description:   ptr("Vault AppRole Secret."),
		Properties: sm.DataAttributeProperties{
			Resource: ptr(sm.Secrets),
			Label:    "AppRole Secret",
			Visible:  true,
			Required: true,
		},
		AttributeCallback: &sm.AttributeCallback{
			Mappings: []sm.AttributeCallbackMapping{
				{
					To:      "SECRET_TYPE.EQUALS",
					Value:   []sm.SecretType{sm.ApiKey, sm.Generic},
					Targets: []sm.AttributeValueTarget{sm.Filter},
				},
			},
		},
	}
	vaultManagementRole = sm.DataAttributeV3{
		Uuid:          "e869cab0-80c9-44a0-900b-51791827edeb",
		Version:       3,
		SchemaVersion: sm.V3,
		Name:          "data_vault_management_role",
		ContentType:   sm.AttributeContentTypeString,
		Description:   ptr("Vault Role."),
		Properties: sm.DataAttributeProperties{
			Label:    "Vault role",
			Visible:  true,
			Required: true,
		},
	}
)

const (
	vaultInfoContentDescrConst         = "Provide URL of your Vault and select one of the available authentication methods:\n-  **AppRole** - Use AppRole authentication method with Role ID and Secret ID\n-  **Kubernetes** - Use Kubernetes authentication method with Service Account Token (automatically taken from the environment)\n-  **JWT/OIDC** - Use JWT/OIDC authentication method with provided JWT token (automatically taken from the environment)"
	vaultProfilesInfoContentDescrConst = "**Vault mount point** - The mount point is the root level \"directory\" where a secrets engine is enabled in Vault.\n\n**Secret path prefix** - Relative path that is prepended to each request. Useful if you don't want to have all the secrets in the root level"
	secretInfoContentDescrConst        = "**Relative secret path** - Relative secret path that is appended to constructed secret path."
)

const (
	VaultManagementCredentialGroupUUID = "2371992e-e074-4128-a53a-a877d6e548c6"
	VaultManagementCredentialGroupName = "group_vault_management_credential"
)

// Metadata attribute definitions
var (
	canonicalSecretPath = sm.MetadataAttributeV3{
		Uuid:        "aa471f64-fa56-448e-8794-7d0cbc06b29d",
		Name:        "meta_canonical_secret_path",
		Description: ptr("Canonical secret path in Vault"),
		Version:     3,
		Type:        sm.Meta,
		ContentType: sm.AttributeContentTypeString,
		Properties: sm.MetadataAttributeProperties{
			Label:     "Canonical secret path",
			Visible:   true,
			Overwrite: ptr(true),
		},
		SchemaVersion: sm.V3,
	}
	keyvalueEngineVersion = sm.MetadataAttributeV3{
		Uuid:        "310387bc-915a-49ae-8425-77f5192bb456",
		Name:        "meta_keyvalue_engine_version",
		Description: ptr("Version of Vault KeyValue secret engine"),
		Version:     3,
		Type:        sm.Meta,
		ContentType: sm.AttributeContentTypeString,
		Properties: sm.MetadataAttributeProperties{
			Label:     "Secret engine version",
			Visible:   true,
			Overwrite: ptr(true),
		},
		SchemaVersion: sm.V3,
	}
)
