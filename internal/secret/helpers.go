package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"
	internalVault "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/vault"

	vcg "github.com/hashicorp/vault-client-go"
	"go.uber.org/zap"
)

func ptr[T any](v T) *T {
	return &v
}

func vaultPath(pathPrefix, secretPath, name string) string {
	var res string
	if pathPrefix != "" {
		res = fmt.Sprintf("%s/", pathPrefix)
	}
	if secretPath != "" {
		res = fmt.Sprintf("%s%s/", res, secretPath)
	}

	return fmt.Sprintf("%s%s", res, name)
}

func toJson(_ context.Context, w http.ResponseWriter, statusCode int, resp any) {
	b, err := json.Marshal(resp)
	if err != nil {
		logger.Get().Error("Failed to marshal structure to json.",
			zap.Error(err),
			zap.Any("structure", resp))
		internal(w, "Failed to marshal structure to json.")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(b)
}

func obtainVClient(ctx context.Context, w http.ResponseWriter, r *http.Request, n Needs) *vcg.Client {
	c, err := n.Client(ctx)
	switch {
	case vcg.IsErrorStatus(err, http.StatusUnauthorized):
		unauthorized(w, fmt.Sprintf("Authentication failed: %s.", err))
		return nil

	case vcg.IsErrorStatus(err, http.StatusForbidden):
		forbidden(w, fmt.Sprintf("Authorization failed: %s.", err))
		return nil

	case err != nil:
		logger.Get().Debug("Could not connect to Vault.",
			zap.Error(err),
			zap.String("http-path", r.URL.Path),
			zap.String("vault-address", n.address),
			zap.String("mount", n.mount))
		badrequest(w, fmt.Sprintf("Could not connect to Vault: %s", err), sm.ATTRIBUTESERROR)
		return nil
	}
	return c
}

func readRBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Get().Error("Calling `io.ReadAll()` failed.", zap.Error(err))
		internal(w, "Reading request body failed.")
		return b, false
	}
	return b, true
}

func unmrshl(w http.ResponseWriter, body []byte, req any) bool {
	if err := json.Unmarshal(body, &req); err != nil {
		logger.Get().Debug("Calling `json.Unmarshal()` failed.", zap.Error(err))
		badrequest(w, "Failed to unmarshal request.", sm.ATTRIBUTESERROR)
		return false
	}
	return true
}

func obtainNeeds(_ context.Context, w http.ResponseWriter, r *http.Request, k8sToken *string, vaultAttrs, vaultProfileAttrs, secretAttrs *[]sm.RequestAttribute) *Needs {
	n := NewNeeds(k8sToken)
	if err := n.Process(r.Context(), vaultAttrs, vaultProfileAttrs, secretAttrs); err != nil {
		logger.Get().Debug("Processing request attributes failed.",
			zap.Error(err),
			zap.String("http-path", r.URL.Path),
			zap.String("vault-address", n.address),
			zap.String("mount", n.mount))
		badrequest(w, fmt.Sprintf("Processing request attributes failed: %s.", err), sm.ATTRIBUTESERROR)
		return nil
	}
	return &n
}

func handleOpError(w http.ResponseWriter, r *http.Request, statusCode int, err error, reqName, reqType, canonicalPath, engineVersion string) (doReturn bool) {
	log := logger.Get()
	switch {
	case errors.Is(err, internalVault.ErrForbidden):
		log.Debug("Authorization failed.", zap.Error(err))
		forbidden(w, "Authorization failed.")
		return true

	case errors.Is(err, internalVault.ErrNotFound):
		log.Debug("Not found.", zap.Error(err))
		notfound(w, err.Error())
		return true

	case errors.Is(err, internalVault.ErrAlreadyExists):
		precondition(w, "Secret already exists.", sm.RESOURCEALREADYEXISTS)
		return true

	case err != nil:
		log.Error("Operation failed.", zap.Error(err), zap.String("http-path", r.URL.Path))
		internal(w, "Operation failed.")
		return true
	}

	if reqName != "" && reqType != "" {
		// canonical secret path
		canonicalSecretPathAttrV3ContentItemV3 := sm.StringAttributeContentV3{
			ContentType: sm.AttributeContentTypeString,
			Data:        canonicalPath,
		}
		var canonicalSecretPathAttrV3ContentItem sm.BaseAttributeContentDtoV3
		if err := canonicalSecretPathAttrV3ContentItem.FromStringAttributeContentV3(canonicalSecretPathAttrV3ContentItemV3); err != nil {
			log.Error("Error marshaling StringAttributeContentV3 into BaseAttributeContentDtoV3.", zap.Error(err), zap.String("http-path", r.URL.Path))
			internal(w, "Operation failed.")
			return true
		}
		canonicalSecretPathAttrV3Content := []sm.BaseAttributeContentDtoV3{canonicalSecretPathAttrV3ContentItem}
		canonicalSecretPathAttrV3 := canonicalSecretPath
		canonicalSecretPathAttrV3.Content = ptr(canonicalSecretPathAttrV3Content)

		var canonicalSecretPathAttr sm.MetadataAttribute
		if err := canonicalSecretPathAttr.FromMetadataAttributeV3(canonicalSecretPathAttrV3); err != nil {
			log.Error("Error marshaling MetadataAttributeV3 into MetadataAttribute.", zap.Error(err), zap.String("http-path", r.URL.Path))
			internal(w, "Operation failed.")
			return true
		}

		// keyvalue engine version
		keyvalueEngineVersionAttrV3ContentItemV3 := sm.StringAttributeContentV3{
			ContentType: sm.AttributeContentTypeString,
			Data:        engineVersion,
		}
		var keyvalueEngineVersionAttrV3ContentItem sm.BaseAttributeContentDtoV3
		if err := keyvalueEngineVersionAttrV3ContentItem.FromStringAttributeContentV3(keyvalueEngineVersionAttrV3ContentItemV3); err != nil {
			log.Error("Error marshaling StringAttributecontentV3 into BaseAttributeContentDtoV3.", zap.Error(err), zap.String("http-path", r.URL.Path))
			internal(w, "Operation failed.")
			return true
		}
		keyvalueEngineVersionAttrV3Content := []sm.BaseAttributeContentDtoV3{keyvalueEngineVersionAttrV3ContentItem}
		keyvalueEngineVersionAttrV3 := keyvalueEngineVersion
		keyvalueEngineVersionAttrV3.Content = ptr(keyvalueEngineVersionAttrV3Content)

		var keyvalueEngineVersionAttr sm.MetadataAttribute
		if err := keyvalueEngineVersionAttr.FromMetadataAttributeV3(keyvalueEngineVersionAttrV3); err != nil {
			log.Error("Error marshaling MetadataAttributeV3 into MetadataAttribute.", zap.Error(err), zap.String("http-path", r.URL.Path))
			internal(w, "Operation failed.")
			return true
		}

		metadata := []sm.MetadataAttribute{canonicalSecretPathAttr, keyvalueEngineVersionAttr}

		toJson(r.Context(), w, statusCode, sm.SecretResponseDto{
			Name:     reqName,
			Type:     sm.SecretType(reqType),
			Metadata: ptr(metadata),
		})
	}

	return false
}
