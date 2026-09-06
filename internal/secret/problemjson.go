package secret

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"

	"go.uber.org/zap"
)

const (
	problemJsonAboutBlankType = "about:blank"
)

func badrequest(w http.ResponseWriter, detail string, ec sm.ErrorCode) {
	t := time.Now()
	p := problem{
		Type:      problemJsonAboutBlankType,
		Title:     "Bad request",
		Status:    http.StatusBadRequest,
		Detail:    detail,
		ErrorCode: ec,
		Timestamp: t.Format(time.RFC3339),
		Retryable: true,
	}

	p.Json(w)
}

func internal(w http.ResponseWriter, detail string) {
	t := time.Now()
	p := problem{
		Type:      problemJsonAboutBlankType,
		Title:     "Internal server error",
		Status:    http.StatusInternalServerError,
		Detail:    detail,
		ErrorCode: sm.SERVICEUNAVAILABLE,
		Timestamp: t.Format(time.RFC3339),
		Retryable: false,
	}

	p.Json(w)
}

func unauthorized(w http.ResponseWriter, detail string) {
	t := time.Now()
	p := problem{
		Type:      problemJsonAboutBlankType,
		Title:     "Unauthorized",
		Status:    http.StatusUnauthorized,
		Detail:    detail,
		ErrorCode: sm.ATTRIBUTESERROR,
		Timestamp: t.Format(time.RFC3339),
		Retryable: false,
	}

	p.Json(w)
}

func forbidden(w http.ResponseWriter, detail string) {
	t := time.Now()
	p := problem{
		Type:      problemJsonAboutBlankType,
		Title:     "Forbidden",
		Status:    http.StatusForbidden,
		Detail:    detail,
		ErrorCode: sm.ATTRIBUTESERROR,
		Timestamp: t.Format(time.RFC3339),
		Retryable: false,
	}

	p.Json(w)
}

func precondition(w http.ResponseWriter, detail string, ec sm.ErrorCode) {
	t := time.Now()
	p := problem{
		Type:      problemJsonAboutBlankType,
		Title:     "Precondition failed",
		Status:    http.StatusPreconditionFailed,
		Detail:    detail,
		ErrorCode: ec,
		Timestamp: t.Format(time.RFC3339),
		Retryable: false,
	}

	p.Json(w)
}

func notfound(w http.ResponseWriter, detail string) {
	t := time.Now()
	p := problem{
		Type:      problemJsonAboutBlankType,
		Title:     "Not found",
		Status:    http.StatusNotFound,
		Detail:    detail,
		ErrorCode: sm.RESOURCENOTFOUND,
		Timestamp: t.Format(time.RFC3339),
		Retryable: false,
	}

	p.Json(w)
}

type problem struct {
	Type      string       `json:"type,omitempty"`
	Title     string       `json:"title,omitempty"`
	Status    int          `json:"status,omitempty"`
	Detail    string       `json:"detail,omitempty"`
	Instance  string       `json:"instance,omitempty"`
	ErrorCode sm.ErrorCode `json:"errorCode,omitempty"`
	Timestamp string       `json:"timestamp,omitempty"`
	Retryable bool         `json:"retryable,omitempty"`
}

func (p problem) Json(w http.ResponseWriter) {
	var err error
	var b []byte
	if b, err = json.Marshal(p); err != nil {
		// this shouldn't happen as we control the annotation of problem struct
		logger.Get().Error("Failed to marshal problem struct to json",
			zap.Error(err), zap.Any("struct", p))
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	if p.Status > 0 {
		w.WriteHeader(p.Status)
	}
	_, _ = w.Write(b)
}
