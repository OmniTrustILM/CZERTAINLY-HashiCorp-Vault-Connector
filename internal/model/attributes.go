package model

import (
	"encoding/json"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"

	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

var log = logger.Get()

const (
	CONNECTOR_KIND = "HVault"

	// Authority Attributes
	AUTHORITY_INFO_ATTR                  string = "34f9569d-eba1-423a-a0c2-995e9c15665d"
	AUTHORITY_URL_ATTR                   string = "8a68156a-d1f5-4322-b2a5-26e872a6fc0e"
	AUTHORITY_CREDENTIAL_TYPE_ATTR       string = "85197836-2ceb-4e77-b14e-53d2e9761cfc"
	AUTHORITY_GROUP_CREDENTIAL_TYPE_ATTR string = "335aede7-dd1f-4c87-9ff8-7dc93f18c5fe"
	AUTHORITY_ROLE_ID_ATTR               string = "97a46e73-bf7d-421d-ae5a-2d0f453eb300"
	AUTHORITY_ROLE_SECRET_ATTR           string = "60daa99e-5b08-4f36-8f51-d136ecba74e9"
	AUTHORITY_VAULT_ROLE_ATTR            string = "7dea8a67-3313-40d9-9eb9-e4af0827c833"
	AUTHORITY_MOUNT_PATH_ATTR            string = "3cb99b1d-b4b2-484e-bca9-c5a9a0f53e96"

	// RA Profile Attributes
	RA_PROFILE_ENGINE_ATTR    string = "e7817459-41cf-40d4-ad3d-9808ef14cad7"
	RA_PROFILE_ROLE_ATTR      string = "389dfa3c-cf45-458e-bca4-507d11b2858c"
	RA_PROFILE_AUTHORITY_ATTR string = "5af5693a-74bf-4ec4-b101-44ce35d8455b"

	// Discovery Attributes
	DISCOVERY_AUTHORITY_ATTR  string = "24531b64-efd2-4a16-8ba8-ffef90890356"
	DISCOVERY_PKI_ENGINE_ATTR string = "12a10e1e-1fdf-4ca5-b65f-68d92ef905a0"
)

type AttributeName string

const (
	KUBERNETES_CRED string = "kubernetes"
	APPROLE_CRED    string = "approle"
	JWTOIDC_CRED    string = "jwt"
)

type CredentialType string

func GetCredentialTypeByName(credentialType string) AttributeContent {
	for _, attribute := range GetCredentialTypes() {
		if attribute.GetData() == credentialType {
			return attribute
		}
	}
	return nil
}
func GetCredentialTypes() []AttributeContent {
	return []AttributeContent{

		StringAttributeContent{
			Reference: "Kubernetes",
			Data:      KUBERNETES_CRED,
		}, StringAttributeContent{
			Reference: "AppRole",
			Data:      APPROLE_CRED,
		}, StringAttributeContent{
			Reference: "JWT/OIDC",
			Data:      JWTOIDC_CRED,
		},
	}
}

func GetAttributeDefByUUID(uuid string) Attribute {
	for _, attr := range GetAttributeList() {
		if attr.GetUuid() == uuid {
			return attr
		}
	}
	return nil
}

func GetAttributeDefByName(name string) Attribute {
	for _, attr := range GetAttributeList() {
		if attr.GetName() == name {
			return attr
		}
	}
	return nil
}

const (
	AuthorityManagementAttributes string = "AuthorityManagementAttributes"
	DisoveryAttributes            string = "DiscoveryAttributes"
	RAProfilesAttributes          string = "RAProfilesAttributes"
)

func GetAttributeListBySet(attributeSet string) []Attribute {
	switch attributeSet {
	case AuthorityManagementAttributes:
		return getAuthorityManagementAttributes()
	case DisoveryAttributes:
		return getDiscoveryAttributes()
	case RAProfilesAttributes:
		return getRAProfilesAttributes()
	}

	return nil
}

func GetAttributeList() []Attribute {
	attributeList := append(getAuthorityManagementAttributes(), getDiscoveryAttributes()...)
	attributeList = append(attributeList, getRAProfilesAttributes()...)
	attributeList = append(attributeList, getAuthorityManagementAttributes()...)
	return attributeList
}

func GetAtributeByUUID(uuid string) AttributeDefinition {
	for _, attr := range GetAttributeList() {
		if attr.GetUuid() == uuid {
			return AttributeDefinition{
				Name:                 attr.GetName(),
				Uuid:                 attr.GetUuid(),
				AttributeType:        attr.GetAttributeType(),
				AttributeContentType: attr.GetAttributeContentType(),
			}
		}
	}
	return AttributeDefinition{}
}

func GetAttributeByName(name string) AttributeDefinition {
	for _, attr := range GetAttributeList() {
		if attr.GetName() == name {
			return AttributeDefinition{
				Name:                 attr.GetName(),
				Uuid:                 attr.GetUuid(),
				AttributeType:        attr.GetAttributeType(),
				AttributeContentType: attr.GetAttributeContentType(),
			}
		}
	}
	return AttributeDefinition{}
}

func unmarshalAttributeContent(content []byte, contentType AttributeContentType) AttributeContent {
	var result AttributeContent
	switch contentType {
	case STRING:
		stringContent := StringAttributeContent{}
		err := json.Unmarshal(content, &stringContent)
		result = stringContent
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
		}
	case OBJECT:
		//TODO: remove conversion to string after UI will be able to handle ObjectAttributeContent
		stringData := StringAttributeContent{}
		err := json.Unmarshal(content, &stringData)
		result = ObjectAttributeContent{
			Reference: stringData.Reference,
			Data:      map[string]any{"objectData": stringData.Data},
		}
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
			objectData := ObjectAttributeContent{}
			err := json.Unmarshal(content, &objectData)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
			result = objectData
		}
	case BOOLEAN:
		booleanContent := BooleanAttributeContent{}
		err := json.Unmarshal(content, &booleanContent)
		result = booleanContent
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
		}

	case SECRET:
		//TODO: remove conversion to string after UI will be able to handle SecretAttributeContentData
		//secretAttributeContent := SecretAttributeContent{}
		stringData := StringAttributeContent{}
		err := json.Unmarshal(content, &stringData)
		result = SecretAttributeContent{
			Reference: stringData.Reference,
			Data: SecretAttributeContentData{
				Secret: stringData.Data,
			},
		}
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
			secretData := SecretAttributeContent{}
			err := json.Unmarshal(content, &secretData)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
			result = secretData
		}
	}

	return result
}

func unmarshalAttribute(content []byte, attrDef AttributeDefinition) Attribute {
	var result Attribute
	switch attrDef.AttributeType {
	case DATA:

		data := DataAttribute{}
		contents := gjson.GetBytes(content, "content")
		for _, content := range contents.Array() {
			data.Content = append(data.Content, unmarshalAttributeContent([]byte(content.Raw), attrDef.AttributeContentType))
		}
		data.Uuid = gjson.GetBytes(content, "uuid").String()
		data.Name = gjson.GetBytes(content, "name").String()
		data.Description = gjson.GetBytes(content, "description").String()
		data.Type = attrDef.AttributeType
		data.ContentType = attrDef.AttributeContentType
		properties := gjson.GetBytes(content, "properties").Raw
		if properties != "" {
			err := json.Unmarshal([]byte(properties), &data.Properties)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
		constraints := gjson.GetBytes(content, "constrains").Raw
		if constraints != "" {
			err := json.Unmarshal([]byte(constraints), &data.Constraints)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
		callbacks := gjson.GetBytes(content, "attributeCallback").Raw
		if callbacks != "" {
			err := json.Unmarshal([]byte(callbacks), &data.AttributeCallback)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
		result = data
	}

	return result
}

func unmarshalAttributeValue(content []byte, attrDef AttributeDefinition) Attribute {
	var result Attribute
	switch attrDef.AttributeType {
	case DATA:
		data := GetAttributeDefByName(attrDef.Name).(DataAttribute)
		contents := gjson.GetBytes(content, "content")
		data.Content = []AttributeContent{}
		for _, content := range contents.Array() {
			data.Content = append(data.Content, unmarshalAttributeContent([]byte(content.Raw), attrDef.AttributeContentType))
		}
		result = data
	}

	return result
}

func UnmarshalAttributesValues(content []byte) []Attribute {
	attributes := gjson.GetBytes(content, "@values")
	var result []Attribute
	for _, attribute := range attributes.Array() {
		def := GetAttributeByName(gjson.Get(attribute.Raw, "name").String())
		attributeObject := unmarshalAttributeValue([]byte(attribute.Raw), def)
		result = append(result, attributeObject)
	}
	return result
}

func UnmarshalAttributes(content []byte) []Attribute {
	attributes := gjson.GetBytes(content, "@values")
	var result []Attribute
	for _, attribute := range attributes.Array() {
		definition := AttributeDefinition{}
		err := json.Unmarshal([]byte(attribute.Raw), &definition)
		if err != nil {
			return nil
		}
		if definition.AttributeType == "" || definition.AttributeContentType == "" {
			def := GetAttributeByName(definition.Name)
			definition.AttributeType = def.AttributeType
			definition.AttributeContentType = def.AttributeContentType
		}
		attributeObject := unmarshalAttribute([]byte(attribute.Raw), definition)
		result = append(result, attributeObject)
	}
	return result
}

func GetAttributeFromArrayByUUID(uuid string, attributes []Attribute) Attribute {
	for _, attr := range attributes {
		if attr.GetUuid() == uuid {
			return attr
		}
	}
	return nil
}

func getRAProfilesAttributes() []Attribute {
	return []Attribute{
		DataAttribute{
			Uuid:        RA_PROFILE_ENGINE_ATTR,
			Name:        "ra_profile_engine",
			Description: "Select PKI secret engine to be used for certificate management",
			Type:        DATA,
			Content:     nil,
			ContentType: OBJECT,
			Properties: &DataAttributeProperties{
				Label:       "PKI secret engine",
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        true,
				MultiSelect: false,
				// Workaround for OmniTrustILM/core#1804: core's strict list validation
				// rejects valid OBJECT content. Revert once core#1804 is fixed.
				ExtensibleList: true,
			},
		},
		DataAttribute{
			Uuid:        RA_PROFILE_AUTHORITY_ATTR,
			Name:        "ra_profile_authority",
			Description: "Helper attribute to pass authority UUID to the callback function",
			Type:        DATA,
			Content:     nil,
			ContentType: STRING,
			Properties: &DataAttributeProperties{
				Label:       "Authority UUID",
				Visible:     false,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        RA_PROFILE_ROLE_ATTR,
			Name:        "ra_profile_role",
			Description: "Select role that defines procedure for generating a certificate",
			Type:        DATA,
			Content:     nil,
			ContentType: STRING,
			Properties: &DataAttributeProperties{
				Label:       "Role",
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        true,
				MultiSelect: false,
				// Workaround for OmniTrustILM/core#1804: core's strict list validation
				// rejects valid OBJECT content. Revert once core#1804 is fixed.
				ExtensibleList: true,
			},
			AttributeCallback: &AttributeCallback{
				CallbackContext: "/v1/authorityProvider/authorities/{uuid}/raProfileRole/{engineName}/callback",
				CallbackMethod:  "GET",
				Mappings: []AttributeCallbackMapping{
					{
						From:                 "ra_profile_engine.data.engineName",
						AttributeType:        DATA,
						AttributeContentType: STRING,
						To:                   "engineName",
						Targets: []AttributeValueTarget{
							PATH_VARIABLE,
						},
					},
					{
						From:                 "ra_profile_authority.data",
						AttributeType:        DATA,
						AttributeContentType: STRING,
						To:                   "uuid",
						Targets: []AttributeValueTarget{
							PATH_VARIABLE,
						},
					},
				},
			},
		},
	}
}

func getDiscoveryAttributes() []Attribute {
	return []Attribute{
		DataAttribute{
			Uuid:        DISCOVERY_AUTHORITY_ATTR,
			Name:        "authority_to_discover",
			Description: "Select Vault to run discovery against",
			Type:        DATA,
			Content:     nil,
			ContentType: OBJECT,
			Properties: &DataAttributeProperties{
				Label:       "Vault",
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        true,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        DISCOVERY_PKI_ENGINE_ATTR,
			Name:        "pki_engines_to_discover",
			Description: "Select authorized PKI secret engines to be used for discovery. If none selected, all authorized PKI secret engines will be used",
			Type:        DATA,
			Content:     nil,
			ContentType: OBJECT,
			Properties: &DataAttributeProperties{
				Label:       "PKI secrets engines",
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        true,
				MultiSelect: true,
			},
			AttributeCallback: &AttributeCallback{
				CallbackContext: "v1/discoveryProvider/{uuid}/pkiengines/callback",
				CallbackMethod:  "GET",
				Mappings: []AttributeCallbackMapping{
					{
						From:                 "authority_to_discover.data.uuid",
						AttributeType:        DATA,
						AttributeContentType: STRING,
						To:                   "uuid",
						Targets: []AttributeValueTarget{
							PATH_VARIABLE,
						},
					},
				},
			},
		},
	}

}

func getAuthorityManagementAttributes() []Attribute {
	return []Attribute{
		InfoAttribute{
			Uuid:        AUTHORITY_INFO_ATTR,
			Name:        "authority_info",
			Description: "Create a new HashiCorp Vault instance configuration",
			Type:        INFO,
			ContentType: TEXT,
			Content: []AttributeContent{
				TextAttributeContent{
					Data: `### HashiCorp Vault instance configuration.

Provide URL of your Vault and select one of the available authentication methods:
-  **AppRole** - Use AppRole authentication method with Role ID and Secret ID
-  **Kubernetes** - Use Kubernetes authentication method with Service Account Token (automatically taken from the environment)
-  **JWT/OIDC** - Use JWT/OIDC authentication method with provided JWT token (automatically taken from the environment)
`,
				},
			},
			Properties: InfoAttributeProperties{
				Label:   "Authority instance configuration",
				Visible: true,
				Group:   "",
			},
		},
		DataAttribute{
			Uuid:        AUTHORITY_URL_ATTR,
			Name:        "authority_url",
			Description: "Vault URL should be in the format http(s)://<vault-url>:<port>",
			Type:        DATA,
			Content:     []AttributeContent{},
			ContentType: STRING,
			Properties: &DataAttributeProperties{
				Label:       "Vault URL",
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
			Constraints: []AttributeConstraint{
				RegexpAttributeConstraint{
					Description:  "URL for the HashiCorp Vault",
					ErrorMessage: "URL must be a valid URL",
					Type:         REG_EXP,
					Data:         "^(http|https)://[a-zA-Z0-9.-]+(:[0-9]+)?",
				},
			},
		},
		DataAttribute{
			Uuid:        AUTHORITY_CREDENTIAL_TYPE_ATTR,
			Name:        "credentials_type",
			Description: "Select one of the available authentication methods",
			Type:        DATA,
			Content:     nil,
			ContentType: STRING,
			Properties: &DataAttributeProperties{
				Label:       "Authentication method",
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        true,
				MultiSelect: false,
			},
		},
		GroupAttribute{
			Uuid:        AUTHORITY_GROUP_CREDENTIAL_TYPE_ATTR,
			Name:        "credential_group",
			Description: "Authentication method data",
			Type:        GROUP,
			AttributeCallback: &AttributeCallback{
				CallbackContext: "v1/authorityProvider/credentialType/{credentialsType}/callback",
				CallbackMethod:  "GET",
				Mappings: []AttributeCallbackMapping{
					{
						From:                 "credentials_type.data",
						AttributeType:        DATA,
						AttributeContentType: STRING,
						To:                   "credentialsType",
						Targets: []AttributeValueTarget{
							PATH_VARIABLE,
						},
					},
				},
			},
		},
		DataAttribute{
			Uuid:        AUTHORITY_ROLE_ID_ATTR,
			Name:        "role_id",
			Description: "Role ID for connection to Vault",
			Type:        DATA,
			Content:     nil,
			ContentType: SECRET,
			Properties: &DataAttributeProperties{
				Label:       "Role ID",
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        AUTHORITY_ROLE_SECRET_ATTR,
			Name:        "role_secret",
			Description: "Role Secret for connection to Vault",
			Type:        DATA,
			Content:     nil,
			ContentType: SECRET,
			Properties: &DataAttributeProperties{
				Label:       "Role Secret",
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        AUTHORITY_VAULT_ROLE_ATTR,
			Name:        "vault_role",
			Description: "Name of the role against which the login is being attempted. If not provided, the default role will be used",
			Type:        DATA,
			Content:     nil,
			ContentType: STRING,
			Properties: &DataAttributeProperties{
				Label:       "Vault Role",
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        AUTHORITY_MOUNT_PATH_ATTR,
			Name:        "mount_path",
			Description: "Mount path for the authentication method. If not provided, the default mount path will be used",
			Type:        DATA,
			Content:     nil,
			ContentType: STRING,
			Properties: &DataAttributeProperties{
				Label:       "Mount Path",
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
	}
}
