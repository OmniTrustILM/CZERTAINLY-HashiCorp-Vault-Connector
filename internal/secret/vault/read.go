package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"

	vcg "github.com/hashicorp/vault-client-go"
	vcgSchema "github.com/hashicorp/vault-client-go/schema"
)

func (m *Manager) Read(ctx context.Context, client *vcg.Client, mount, path string, secretType sm.SecretType) (sm.SecretContent, error) {
	u := lockRef(mount, path)
	m.locks.RLock(u)
	defer m.locks.RUnlock(u)

	var err error
	v, err := DetectKVVersion(ctx, client, mount)
	if err != nil {
		return sm.SecretContent{}, err
	}

	var resp any

	switch v {
	case KVVersionV1:

		resp, err = client.Secrets.KvV1Read(ctx, path, vcg.WithMountPath(mount))

	case KVVersionV2:
		resp, err = client.Secrets.KvV2Read(ctx, path, vcg.WithMountPath(mount))

	default:
		return sm.SecretContent{}, errors.New("unknown kv engine version")
	}

	if err != nil {
		return sm.SecretContent{}, toPkgErr(err)
	}

	var sc sm.SecretContent
	sc, err = FromPayload(resp, secretType)
	if err != nil {
		return sc, err
	}
	return sc, nil
}

func FromPayload(payload any, secretType sm.SecretType) (sm.SecretContent, error) {
	var data map[string]any

	switch v := payload.(type) {
	case *vcg.Response[map[string]any]:
		data = v.Data
	case *vcg.Response[vcgSchema.KvV2ReadResponse]:
		data = v.Data.Data
	default:
		return sm.SecretContent{}, fmt.Errorf("unexpected response payload type %T from `hashicorp/vault-client-go`", v)
	}

	sc := sm.SecretContent{}
	switch secretType {
	case sm.ApiKey:
		apiKeyEncoded, err := fromCommonContentPayload(data, secretType)
		if err != nil {
			return sc, err
		}
		if err := sc.FromApiKeySecretContent(sm.ApiKeySecretContent{
			Content: apiKeyEncoded,
		}); err != nil {
			return sc, fmt.Errorf("marshaling ApiKeySecret into SecretContent union failed: %w", err)
		}
		return sc, nil

	case sm.BasicAuth:
		username, password, err := fromBasicAuthPayload(data)
		if err != nil {
			return sc, err
		}
		if err := sc.FromBasicAuthSecretContent(sm.BasicAuthSecretContent{
			Username: username,
			Password: password,
		}); err != nil {
			return sc, fmt.Errorf("marshaling BasicAuthSecret into SecretContent union failed: %w", err)
		}
		return sc, nil

	case sm.Generic:
		generic, err := fromGenericPayload(data)
		if err != nil {
			return sc, err
		}
		if err := sc.FromGenericSecretContent(sm.GenericSecretContent{
			Content: generic,
		}); err != nil {
			return sc, fmt.Errorf("marshaling GenericSecret into SecretContent union failed: %w", err)
		}
		return sc, nil

	case sm.JwtToken:
		jwtToken, err := fromCommonContentPayload(data, secretType)
		if err != nil {
			return sc, err
		}
		if err := sc.FromJwtTokenSecretContent(sm.JwtTokenSecretContent{
			Content: jwtToken,
		}); err != nil {
			return sc, fmt.Errorf("marshaling JwtTokenSecret into SecretContent union failed: %w", err)
		}
		return sc, nil

	case sm.KeyStore:
		content, password, keyStoreType, err := fromKeyStorePayload(data)
		if err != nil {
			return sc, err
		}
		if err := sc.FromKeyStoreSecretContent(sm.KeyStoreSecretContent{
			Content:      content,
			KeyStoreType: keyStoreType,
			Password:     password,
		}); err != nil {
			return sc, fmt.Errorf("marshaling KeyStoreSecret into SecretContent union failed: %w", err)
		}
		return sc, nil

	case sm.KeyValue:
		if err := sc.FromKeyValueSecretContent(sm.KeyValueSecretContent{
			Content: data,
		}); err != nil {
			return sc, fmt.Errorf("marshaling KeyValueSecret into SecretContent union failed: %w", err)
		}
		return sc, nil

	case sm.PrivateKey:
		privateKey, err := fromCommonContentPayload(data, secretType)
		if err != nil {
			return sc, err
		}
		if !isPemFormat([]byte(privateKey)) {
			return sc, fmt.Errorf("%w: not PEM format", ErrNotDeclaredType)
		}
		if err := sc.FromPrivateKeySecretContent(sm.PrivateKeySecretContent{
			Content: base64.StdEncoding.EncodeToString([]byte(privateKey)),
		}); err != nil {
			return sc, fmt.Errorf("marshaling PrivateKeySecret into SecretContent union failed: %w", err)
		}
		return sc, nil

	case sm.SecretKey:
		secretKey, err := fromCommonContentPayload(data, secretType)
		if err != nil {
			return sc, err
		}
		if err := sc.FromSecretKeySecretContent(sm.SecretKeySecretContent{
			Content: secretKey,
		}); err != nil {
			return sc, fmt.Errorf("marshaling SecretKeySecret into SecretContent union failed: %w", err)
		}
		return sc, nil
	}

	return sc, fmt.Errorf("unknown secret type %q", secretType)
}

func fromKeyStorePayload(payload map[string]any) (string, string, sm.KeyStoreType, error) {
	var ok bool
	var content, password, keyStoreTypeStr string
	var keyStoreType sm.KeyStoreType

	_, ok = payload[ContentKey]
	if !ok {
		return "", "", keyStoreType, fmt.Errorf("%w: %q expects key %q", ErrNotDeclaredType, sm.KeyStore, ContentKey)
	}
	content, ok = payload[ContentKey].(string)
	if !ok {
		return "", "", keyStoreType, fmt.Errorf("%w: %q expects value of the key %q to be a string", ErrNotDeclaredType, sm.KeyStore, ContentKey)
	}

	_, ok = payload[PasswordKey]
	if !ok {
		return "", "", keyStoreType, fmt.Errorf("%w: %q expects key %q", ErrNotDeclaredType, sm.KeyStore, PasswordKey)
	}
	password, ok = payload[PasswordKey].(string)
	if !ok {
		return "", "", keyStoreType, fmt.Errorf("%w: %q expects value of the key %q to be a string", ErrNotDeclaredType, sm.KeyStore, PasswordKey)
	}

	_, ok = payload[KeyStoreTypeKey]
	if !ok {
		return "", "", keyStoreType, fmt.Errorf("%w: %q expects key %q", ErrNotDeclaredType, sm.KeyStore, KeyStoreTypeKey)
	}
	keyStoreTypeStr, ok = payload[KeyStoreTypeKey].(string)
	if !ok {
		return "", "", keyStoreType, fmt.Errorf("%w: %q expects value of the key %q to be a string", ErrNotDeclaredType, sm.KeyStore, KeyStoreTypeKey)
	}
	switch {
	case keyStoreTypeStr == string(sm.JKS):
		keyStoreType = sm.JKS
	case keyStoreTypeStr == string(sm.PKCS12):
		keyStoreType = sm.PKCS12
	default:
		return "", "", keyStoreType, fmt.Errorf("%w: %q expects value of the key %q to be one of [\"JKS\", \"PKCS12\"]", ErrNotDeclaredType, sm.KeyStore, KeyStoreTypeKey)
	}

	return content, password, keyStoreType, nil
}

func fromCommonContentPayload(payload map[string]any, secretType sm.SecretType) (string, error) {
	var ok bool
	var content string

	_, ok = payload[ContentKey]
	if !ok {
		return "", fmt.Errorf("%w: %q expects key %q", ErrNotDeclaredType, secretType, ContentKey)
	}
	content, ok = payload[ContentKey].(string)
	if !ok {
		return "", fmt.Errorf("%w: %q expects value of the key %q to be a string", ErrNotDeclaredType, secretType, ContentKey)
	}
	return content, nil
}

func fromGenericPayload(payload map[string]any) (string, error) {
	var ok bool
	var value string

	if len(payload) != 1 {
		return "", fmt.Errorf("%w: %q expects one key/value pair", ErrNotDeclaredType, sm.Generic)
	}
	for k, v := range payload {
		if value, ok = v.(string); ok {
			return value, nil
		} else {
			return "", fmt.Errorf("%w: %q expects value of the key %q to be a string", ErrNotDeclaredType, sm.Generic, k)
		}
	}
	return "", fmt.Errorf("processing %q payload %q failed", sm.Generic, payload)
}

func fromBasicAuthPayload(payload map[string]any) (string, string, error) {
	var ok bool
	var username, password string

	_, ok = payload[UsernameKey]
	if !ok {
		return "", "", fmt.Errorf("%w: %q expects key %q", ErrNotDeclaredType, sm.BasicAuth, UsernameKey)
	}
	username, ok = payload[UsernameKey].(string)
	if !ok {
		return "", "", fmt.Errorf("%w: %q expects value of the key %q to be a string", ErrNotDeclaredType, sm.BasicAuth, UsernameKey)
	}
	_, ok = payload[PasswordKey]
	if !ok {
		return "", "", fmt.Errorf("%w: %q expects key %q", ErrNotDeclaredType, sm.BasicAuth, PasswordKey)
	}
	password, ok = payload[PasswordKey].(string)
	if !ok {
		return "", "", fmt.Errorf("%w: %q expects value of the key %q to be a string", ErrNotDeclaredType, sm.BasicAuth, PasswordKey)
	}
	return username, password, nil
}
