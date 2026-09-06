package vault

import (
	"context"
	"encoding/pem"
	"fmt"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"

	vcg "github.com/hashicorp/vault-client-go"
	vcgSchema "github.com/hashicorp/vault-client-go/schema"
	"github.com/moby/locker/v2"
	"github.com/stretchr/objx"
	"go.uber.org/zap"
)

type Manager struct {
	locks locker.RWMutexMap[string]
}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) ListVisibleMounts(ctx context.Context, client *vcg.Client) ([]string, error) {
	var err error
	resp := []string{}

	var mounts *vcg.Response[vcgSchema.InternalUiListEnabledVisibleMountsResponse]
	if mounts, err = client.System.InternalUiListEnabledVisibleMounts(ctx); err != nil {
		return resp, toPkgErr(err)
	}

	for k, v := range mounts.Data.Secret {
		obj := objx.New(v)
		if !obj.Get("type").IsStr() {
			logger.Get().Warn("Unexpected mount info structure, expected type of key `type` is string.",
				zap.String("mount", k), zap.Any("info", v))
			continue
		}

		if obj.Get("type").Str() != mountInfoTypeKVString {
			continue
		}

		resp = append(resp, k)
	}

	if len(resp) == 0 {
		return resp, fmt.Errorf("%w: zero mount points listed for given credentials", ErrNotFound)
	}

	return resp, nil
}

func ToPayload(ctx context.Context, secret sm.SecretContent) (map[string]any, sm.SecretType, error) {
	secretType, err := secret.Discriminator()
	if err != nil {
		return nil, sm.SecretType(secretType), fmt.Errorf("unmarshalling discriminator field for SecretContent failed: %w", err)
	}

	switch sm.SecretType(secretType) {
	case sm.ApiKey:
		apiKeyContent, err := sm.GetApiKeySecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		return map[string]any{
			ContentKey: apiKeyContent,
		}, sm.SecretType(secretType), nil

	case sm.BasicAuth:
		username, password, err := sm.GetBasicAuthSecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		return map[string]any{
			UsernameKey: username,
			PasswordKey: password,
		}, sm.SecretType(secretType), nil

	case sm.Generic:
		content, err := sm.GetGenericSecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		return map[string]any{
			ContentKey: content,
		}, sm.SecretType(secretType), nil

	case sm.JwtToken:
		content, err := sm.GetJwtTokenSecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		return map[string]any{
			ContentKey: content,
		}, sm.SecretType(secretType), nil

	case sm.KeyStore:
		keyStoreType, content, password, err := sm.GetKeyStoreSecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		return map[string]any{
			KeyStoreTypeKey: keyStoreType,
			ContentKey:      content,
			PasswordKey:     password,
		}, sm.SecretType(secretType), nil

	case sm.KeyValue:
		content, err := sm.GetKeyValueSecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		return content, sm.SecretType(secretType), nil

	case sm.PrivateKey:
		decoded, err := sm.GetPrivateKeySecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		if !isPemFormat(decoded) {
			return nil, sm.SecretType(secretType), fmt.Errorf("%w: not PEM format", ErrNotDeclaredType)
		}
		return map[string]any{
			ContentKey: string(decoded),
		}, sm.SecretType(secretType), nil

	case sm.SecretKey:
		secretKeyContent, err := sm.GetSecretKeySecretContent(secret)
		if err != nil {
			return nil, sm.SecretType(secretType), err
		}
		return map[string]any{
			ContentKey: secretKeyContent,
		}, sm.SecretType(secretType), nil
	}
	return nil, sm.SecretType(secretType), fmt.Errorf("unknown secret type %q", secretType)
}

func isPemFormat(pk []byte) bool {
	block, _ := pem.Decode(pk)
	return block != nil
}

func lockRef(mount, path string) string {
	return fmt.Sprintf("%s%s", mount, path)
}
