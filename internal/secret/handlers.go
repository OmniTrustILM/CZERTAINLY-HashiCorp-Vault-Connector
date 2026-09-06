package secret

import (
	"fmt"
	"net/http"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"

	"go.uber.org/zap"
)

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request) {
	crtBody, ok := readRBody(w, r)
	if !ok {
		return
	}

	var req sm.CreateSecretRequestDto
	if ok := unmrshl(w, crtBody, &req); !ok {
		return
	}

	n := obtainNeeds(r.Context(), w, r, s.k8sToken, req.VaultAttributes, req.VaultProfileAttributes, req.SecretAttributes)
	if n == nil {
		return
	}

	if err := n.CommonCheck(); err != nil {
		badrequest(w, fmt.Sprintf("Missing request attribute or validation failed: %s.", err), sm.VALIDATIONFAILED)
		return
	}

	c := obtainVClient(r.Context(), w, r, *n)
	if c == nil {
		return
	}

	scrtType, canonicalPath, engineVersion, err := s.m.Create(r.Context(), c, n.mount, vaultPath(n.pathPrefix, n.secretPath, req.Name), req.Secret)
	if err == nil {
		logger.FromCtx(r.Context()).Info("Secret created.",
			zap.String("name", req.Name),
			zap.String("type", string(scrtType)),
			zap.String("path", canonicalPath),
			zap.String("engine", engineVersion))
	}
	_ = handleOpError(w, r, http.StatusCreated, err, req.Name, string(scrtType), canonicalPath, engineVersion)
}

func (s *Server) updateSecret(w http.ResponseWriter, r *http.Request) {
	uptdBody, ok := readRBody(w, r)
	if !ok {
		return
	}

	var req sm.UpdateSecretRequestDto
	if ok := unmrshl(w, uptdBody, &req); !ok {
		return
	}

	n := obtainNeeds(r.Context(), w, r, s.k8sToken, req.VaultAttributes, req.VaultProfileAttributes, req.SecretAttributes)
	if n == nil {
		return
	}

	if err := n.CommonCheck(); err != nil {
		badrequest(w, fmt.Sprintf("Missing request attribute or validation failed: %s.", err), sm.VALIDATIONFAILED)
		return
	}

	c := obtainVClient(r.Context(), w, r, *n)
	if c == nil {
		return
	}

	secretType, canonicalPath, engineVersion, err := s.m.Update(r.Context(), c, n.mount, vaultPath(n.pathPrefix, n.secretPath, req.Name), req.Secret)
	if err == nil {
		logger.FromCtx(r.Context()).Info("Secret updated.",
			zap.String("name", req.Name),
			zap.String("type", string(secretType)),
			zap.String("path", canonicalPath),
			zap.String("engine", engineVersion))
	}
	_ = handleOpError(w, r, http.StatusOK, err, req.Name, string(secretType), canonicalPath, engineVersion)
}

func (s *Server) getSecretValue(w http.ResponseWriter, r *http.Request) {
	getBody, ok := readRBody(w, r)
	if !ok {
		return
	}

	var req sm.SecretRequestDto
	if ok := unmrshl(w, getBody, &req); !ok {
		return
	}

	n := obtainNeeds(r.Context(), w, r, s.k8sToken, req.VaultAttributes, req.VaultProfileAttributes, req.SecretAttributes)
	if n == nil {
		return
	}

	if err := n.CommonCheck(); err != nil {
		badrequest(w, fmt.Sprintf("Missing request attribute or validation failed: %s.", err), sm.VALIDATIONFAILED)
		return
	}

	c := obtainVClient(r.Context(), w, r, *n)
	if c == nil {
		return
	}

	sc, err := s.m.Read(r.Context(), c, n.mount, vaultPath(n.pathPrefix, n.secretPath, req.Name), req.Type)
	if handleOpError(w, r, 0, err, "", "", "", "") {
		return
	}

	logger.FromCtx(r.Context()).Debug("Secret content retrieved.",
		zap.String("name", req.Name))

	toJson(r.Context(), w, http.StatusOK, sm.SecretContentResponseDto{
		Content: sc,
	})
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	b, ok := readRBody(w, r)
	if !ok {
		return
	}

	var req sm.SecretRequestDto
	if ok := unmrshl(w, b, &req); !ok {
		return
	}

	n := obtainNeeds(r.Context(), w, r, s.k8sToken, req.VaultAttributes, req.VaultProfileAttributes, req.SecretAttributes)
	if n == nil {
		return
	}

	if err := n.CommonCheck(); err != nil {
		badrequest(w, fmt.Sprintf("Missing request attribute or validation failed: %s.", err), sm.VALIDATIONFAILED)
		return
	}

	c := obtainVClient(r.Context(), w, r, *n)
	if c == nil {
		return
	}

	err := s.m.Delete(r.Context(), c, n.mount, vaultPath(n.pathPrefix, n.secretPath, req.Name))
	if doReturn := handleOpError(w, r, http.StatusNoContent, err, "", "", "", ""); doReturn {
		return
	}

	logger.FromCtx(r.Context()).Info("Secret deleted.",
		zap.String("name", req.Name))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateSecretValue(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Not implemented yet.", http.StatusNotImplemented)
}
func (s *Server) getRotateAttributes(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Not implemented yet.", http.StatusNotImplemented)
}
