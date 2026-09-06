package vault

import (
	"context"
	"errors"
	"strings"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/hashicorp/vault-client-go"
)

// ListPkiEngines returns the PKI secret engines enabled on the vault behind
// client, as attribute content describing each engine. Mounts of any other
// type, and mounts whose description does not have the expected shape, are
// skipped.
func ListPkiEngines(ctx context.Context, client *vault.Client) ([]model.AttributeContent, error) {
	// Due to the nature of its intended usage, there is no guarantee on
	// backwards compatibility for this endpoint.
	mounts, err := client.System.InternalUiListEnabledVisibleMounts(ctx)
	if err != nil {
		return nil, err
	}
	if mounts == nil {
		return nil, errors.New("the vault returned no mount information")
	}

	var engines []model.AttributeContent
	for mountPath, mountData := range mounts.Data.Secret {
		data, ok := mountData.(map[string]any)
		if !ok || data["type"] != "pki" {
			continue
		}

		engineName := strings.TrimSuffix(mountPath, "/")
		engines = append(engines, model.ObjectAttributeContent{
			Reference: engineName,
			Data: map[string]any{
				"engineName":           engineName,
				"engineAccesor":        data["accessor"],
				"runningPluginVersion": data["running_plugin_version"],
			},
		})
	}

	return engines, nil
}

// ListPkiEngineNames returns the names of the PKI secret engines enabled on
// the vault behind client.
func ListPkiEngineNames(ctx context.Context, client *vault.Client) ([]string, error) {
	engines, err := ListPkiEngines(ctx, client)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(engines))
	for _, engine := range engines {
		names = append(names, engine.(model.ObjectAttributeContent).Reference)
	}

	return names, nil
}
