package authority

import (
	"errors"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"strings"
	"unicode"
)

const (
	invalidRAProfileEngineMessage = "Invalid RA profile engine attribute"
	invalidRAProfileRoleMessage   = "Invalid RA profile role attribute"
)

var (
	errInvalidRAProfileEngine = errors.New("invalid RA profile engine attribute")
	errInvalidRAProfileRole   = errors.New("invalid RA profile role attribute")
)

func getRAProfileEngineName(attributes []model.Attribute) (string, error) {
	attribute := model.GetAttributeFromArrayByUUID(model.RA_PROFILE_ENGINE_ATTR, attributes)
	if attribute == nil {
		return "", errInvalidRAProfileEngine
	}

	content := attribute.GetContent()
	if len(content) != 1 {
		return "", errInvalidRAProfileEngine
	}

	engineData, ok := content[0].GetData().(map[string]any)
	if !ok {
		return "", errInvalidRAProfileEngine
	}

	engineName, ok := engineData["engineName"].(string)
	if !ok || !isValidVaultMountPath(engineName) {
		return "", errInvalidRAProfileEngine
	}

	return engineName, nil
}

func getRAProfileRoleName(attributes []model.Attribute) (string, error) {
	attribute := model.GetAttributeFromArrayByUUID(model.RA_PROFILE_ROLE_ATTR, attributes)
	if attribute == nil {
		return "", errInvalidRAProfileRole
	}

	content := attribute.GetContent()
	if len(content) != 1 {
		return "", errInvalidRAProfileRole
	}

	roleName, ok := content[0].GetData().(string)
	if !ok || !isValidVaultPathSegment(roleName) {
		return "", errInvalidRAProfileRole
	}

	return roleName, nil
}

func isValidVaultPathSegment(value string) bool {
	return !strings.Contains(value, "/") && isValidVaultMountPath(value)
}

func isValidVaultMountPath(path string) bool {
	if path == "" || path != strings.TrimSpace(path) || strings.Contains(path, "..") || strings.ContainsAny(path, `\?#%`) {
		return false
	}
	if strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." {
			return false
		}
	}
	return true
}
