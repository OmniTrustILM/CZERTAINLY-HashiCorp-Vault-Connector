package secret

import (
	"fmt"
	"net/http"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func getSecretAttributes(w http.ResponseWriter, r *http.Request) {
	resp := []sm.BaseAttributeDtoV3{}
	log := logger.Get()

	secretsInfoContent := []sm.BaseAttributeContentDtoV3{}
	var secretsInfoContentDescr sm.BaseAttributeContentDtoV3

	if err := secretsInfoContentDescr.FromTextAttributeContentV3(sm.TextAttributeContentV3{
		Data: secretInfoContentDescrConst,
	}); err != nil {
		log.Error("Error marshaling TextAttributeContentV3 into BaseAttributeContentDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	secretsInfoContent = append(secretsInfoContent, secretsInfoContentDescr)

	var secretsInfo sm.BaseAttributeDtoV3
	secretsInfoAttr := secretManagementInfo
	secretsInfoAttr.Content = secretsInfoContent
	if err := secretsInfo.FromInfoAttributeV3(secretsInfoAttr); err != nil {
		log.Error("Error marshaling InfoAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, secretsInfo)

	var secretPath sm.BaseAttributeDtoV3
	if err := secretPath.FromDataAttributeV3(secretManagementPath); err != nil {
		log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, secretPath)

	toJson(r.Context(), w, http.StatusOK, resp)
}

func (s *Server) listVaultProfileAttributes(w http.ResponseWriter, r *http.Request) {
	lvpBody, ok := readRBody(w, r)
	if !ok {
		return
	}

	lvpReq := []sm.RequestAttribute{}
	if ok := unmrshl(w, lvpBody, &lvpReq); !ok {
		return
	}

	n := obtainNeeds(r.Context(), w, r, s.k8sToken, &lvpReq, nil, nil)
	if n == nil {
		return
	}

	if err := n.ConnectionCheck(); err != nil {
		badrequest(w, fmt.Sprintf("Missing request attribute or validation failed: %s.", err), sm.VALIDATIONFAILED)
		return
	}

	c := obtainVClient(r.Context(), w, r, *n)
	if c == nil {
		return
	}

	mnts, err := s.m.ListVisibleMounts(r.Context(), c)
	if handleOpError(w, r, 0, err, "", "", "", "") {
		return
	}

	log := logger.Get()
	var resp []sm.BaseAttributeDtoV3

	vaultProfilesInfoContent := []sm.BaseAttributeContentDtoV3{}
	var vaultProfilesInfoContentDescr sm.BaseAttributeContentDtoV3

	if err := vaultProfilesInfoContentDescr.FromTextAttributeContentV3(sm.TextAttributeContentV3{
		Data: vaultProfilesInfoContentDescrConst,
	}); err != nil {
		log.Error("Error marshaling TextAttributeContentV3 into BaseAttributeContentDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	vaultProfilesInfoContent = append(vaultProfilesInfoContent, vaultProfilesInfoContentDescr)

	var vaultInfo sm.BaseAttributeDtoV3
	vaultProfilesInfoAttr := vaultManagementProfileInfo
	vaultProfilesInfoAttr.Content = vaultProfilesInfoContent
	if err := vaultInfo.FromInfoAttributeV3(vaultProfilesInfoAttr); err != nil {
		log.Error("Error marshaling InfoAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, vaultInfo)

	vaultManagementMountAttr := vaultManagementProfileMount
	vaultManagementMountAttrContent := []sm.BaseAttributeContentDtoV3{}
	for _, cpy := range mnts {
		item := sm.BaseAttributeContentDtoV3{}
		if err := item.FromStringAttributeContentV3(sm.StringAttributeContentV3{Data: cpy}); err != nil {
			log.Error("Error marshaling StringAttributeContentV3 into BaseAttributeContentDtoV3", zap.Error(err))
			internal(w, "Marshaling data structure failed.")
			return
		}
		vaultManagementMountAttrContent = append(vaultManagementMountAttrContent, item)
	}

	vaultManagementMountAttr.Content = &vaultManagementMountAttrContent

	var vaultMount sm.BaseAttributeDtoV3
	if err := vaultMount.FromDataAttributeV3(vaultManagementMountAttr); err != nil {
		log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, vaultMount)

	var vaultPath sm.BaseAttributeDtoV3
	if err := vaultPath.FromDataAttributeV3(vaultManagementProfilePath); err != nil {
		log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, vaultPath)

	toJson(r.Context(), w, http.StatusOK, resp)
}

func (s *Server) listVaultAttributes(w http.ResponseWriter, r *http.Request) {
	log := logger.Get()
	var resp []sm.BaseAttributeDtoV3

	vaultInfoContent := []sm.BaseAttributeContentDtoV3{}
	var vaultInfoContentDescr sm.BaseAttributeContentDtoV3
	if err := vaultInfoContentDescr.FromTextAttributeContentV3(sm.TextAttributeContentV3{
		Data: vaultInfoContentDescrConst,
	}); err != nil {
		log.Error("Error marshaling TextAttributeContentV3 into BaseAttributeContentDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	vaultInfoContent = append(vaultInfoContent, vaultInfoContentDescr)

	var vaultInfo sm.BaseAttributeDtoV3
	vaultInfoAttr := vaultManagementInfo
	vaultInfoAttr.Content = vaultInfoContent
	if err := vaultInfo.FromInfoAttributeV3(vaultInfoAttr); err != nil {
		log.Error("Error marshaling InfoAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, vaultInfo)

	var vaultManagementURIRegexConstraint sm.BaseAttributeConstraint
	if err := vaultManagementURIRegexConstraint.FromRegexpAttributeConstraint(sm.RegexpAttributeConstraint{
		Data:         ptr("^(http|https)://[a-zA-Z0-9.-]+(:[0-9]+)?"),
		Description:  ptr("URL for the HashiCorp Vault"),
		ErrorMessage: ptr("URL must be a valid URL"),
	}); err != nil {
		log.Error("Error marshaling RegexpAttribute into BaseAttributeConstraint", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	vaultManagementURIConstraints := []sm.BaseAttributeConstraint{vaultManagementURIRegexConstraint}
	vaultManagementURIAttr := vaultManagementURI
	vaultManagementURIAttr.Constraints = &vaultManagementURIConstraints

	var vaultURI sm.BaseAttributeDtoV3
	if err := vaultURI.FromDataAttributeV3(vaultManagementURIAttr); err != nil {
		log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, vaultURI)

	var vaultNamespace sm.BaseAttributeDtoV3
	if err := vaultNamespace.FromDataAttributeV3(vaultManagementNamespace); err != nil {
		log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, vaultNamespace)

	// auth methods

	credentialTypeContent := []sm.BaseAttributeContentDtoV3{}

	var appRole sm.BaseAttributeContentDtoV3
	if err := appRole.FromStringAttributeContentV3(credentialTypeAppRole); err != nil {
		log.Error("Error marshaling StringAttributeContentV3 into BaseAttributeContentDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	credentialTypeContent = append(credentialTypeContent, appRole)

	if s.k8sToken != nil {
		var jwtToken sm.BaseAttributeContentDtoV3
		if err := jwtToken.FromStringAttributeContentV3(credentialTypeJwt); err != nil {
			log.Error("Error marshaling StringAttributeContentV3 into BaseAttributeContentDtoV3", zap.Error(err))
			internal(w, "Marshaling data structure failed.")
			return
		}
		credentialTypeContent = append(credentialTypeContent, jwtToken)

		var kubernetes sm.BaseAttributeContentDtoV3
		if err := kubernetes.FromStringAttributeContentV3(credentialTypeK8s); err != nil {
			log.Error("Error marshaling StringAttributeContentV3 into BaseAttributeContentDtoV3", zap.Error(err))
			internal(w, "Marshaling data structure failed.")
			return
		}
		credentialTypeContent = append(credentialTypeContent, kubernetes)
	}

	var credentialType sm.BaseAttributeDtoV3
	ctcpy := vaultManagementCredentialType
	ctcpy.Content = &credentialTypeContent
	if err := credentialType.FromDataAttributeV3(ctcpy); err != nil {
		log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, credentialType)

	credentialGroupAttrType := sm.Data
	credentialGroupAttrContentType := sm.AttributeContentTypeString
	credentialGroupVersion := int32(3)

	var credentialGroup sm.BaseAttributeDtoV3
	if err := credentialGroup.FromGroupAttributeV3(sm.GroupAttributeV3{
		Uuid:          VaultManagementCredentialGroupUUID,
		Version:       &credentialGroupVersion,
		SchemaVersion: sm.V3,
		Name:          VaultManagementCredentialGroupName,
		AttributeCallback: &sm.AttributeCallback{
			CallbackContext: ptr("v1/secretProvider/credentialType/{credentialsType}/callback"),
			CallbackMethod:  ptr("GET"),
			Mappings: []sm.AttributeCallbackMapping{
				{
					From:                 ptr(fmt.Sprintf("%s.data", vaultManagementCredentialType.Name)),
					AttributeType:        &credentialGroupAttrType,
					AttributeContentType: &credentialGroupAttrContentType,
					To:                   "credentialsType",
					Targets: []sm.AttributeValueTarget{
						sm.PathVariable,
					},
				},
			},
		},
	}); err != nil {
		log.Error("Error marshaling GroupAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
		internal(w, "Marshaling data structure failed.")
		return
	}
	resp = append(resp, credentialGroup)

	toJson(r.Context(), w, http.StatusOK, resp)
}

func (s *Server) credentialsType(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	credType := vars["credentialsType"]

	log := logger.Get()

	var resp []sm.BaseAttributeDtoV3

	switch credType {
	case credentialTypeAppRole.Data:
		var roleID sm.BaseAttributeDtoV3
		if err := roleID.FromDataAttributeV3(vaultManagementRoleID); err != nil {
			log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
			internal(w, "Marshaling data structure failed.")
			return
		}
		resp = append(resp, roleID)

		var roleSecret sm.BaseAttributeDtoV3
		if err := roleSecret.FromDataAttributeV3(vaultManagementRoleSecret); err != nil {
			log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
			internal(w, "Marshaling data structure failed.")
			return
		}
		resp = append(resp, roleSecret)

	case credentialTypeJwt.Data:
		fallthrough

	case credentialTypeK8s.Data:
		if s.k8sToken == nil {
			badrequest(w, fmt.Sprintf("Credential type unknown: %s.", credType), sm.VALIDATIONFAILED)
			return
		}
		var role sm.BaseAttributeDtoV3
		if err := role.FromDataAttributeV3(vaultManagementRole); err != nil {
			log.Error("Error marshaling DataAttributeV3 into BaseAttributeDtoV3", zap.Error(err))
			internal(w, "Marshaling data structure failed.")
			return
		}
		resp = append(resp, role)

	default:
		badrequest(w, fmt.Sprintf("Credential type unknown: %s.", credType), sm.VALIDATIONFAILED)
		return
	}

	toJson(r.Context(), w, http.StatusOK, resp)
}
