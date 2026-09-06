package secret

import (
	"fmt"
	"net/http"

	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"
)

func (s *Server) checkVaultConnection(w http.ResponseWriter, r *http.Request) {
	ckBody, ok := readRBody(w, r)
	if !ok {
		return
	}

	req := []sm.RequestAttribute{}
	if ok := unmrshl(w, ckBody, &req); !ok {
		return
	}

	n := obtainNeeds(r.Context(), w, r, s.k8sToken, &req, nil, nil)
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

	_, err := s.m.ListVisibleMounts(r.Context(), c)
	if handleOpError(w, r, 0, err, "", "", "", "") {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
