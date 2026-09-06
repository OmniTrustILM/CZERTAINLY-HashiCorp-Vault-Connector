package vault

import (
	"context"
	"errors"
	"fmt"

	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"

	vcg "github.com/hashicorp/vault-client-go"
	vcgSchema "github.com/hashicorp/vault-client-go/schema"
)

func commonCreateUpdate(ctx context.Context, client *vcg.Client, mount string, secret sm.SecretContent) (KVVersion, map[string]any, sm.SecretType, error) {
	v, err := DetectKVVersion(ctx, client, mount)
	if err != nil {
		return v, map[string]any{}, sm.SecretType(""), err
	}

	payload, secretType, err := ToPayload(ctx, secret)
	return v, payload, secretType, err
}

func (m *Manager) Update(ctx context.Context, client *vcg.Client, mount, path string, secret sm.SecretContent) (sm.SecretType, string, string, error) {
	updateLock := lockRef(mount, path)
	m.locks.Lock(updateLock)
	defer m.locks.Unlock(updateLock)

	v, payload, secretType, err := commonCreateUpdate(ctx, client, mount, secret)
	if err != nil {
		return secretType, "", "", err
	}

	canonicalPath := fmt.Sprintf("%s%s", mount, path)

	switch v {
	case KVVersionV1:

		_, err = client.Secrets.KvV1Read(ctx, path, vcg.WithMountPath(mount))
		if err != nil {
			return secretType, canonicalPath, KVVersionV1.String(), toPkgErr(err)
		}

		_, err := client.Secrets.KvV1Write(ctx, path, payload, vcg.WithMountPath(mount))
		if err != nil {
			return secretType, canonicalPath, KVVersionV1.String(), toPkgErr(err)
		}
		return secretType, canonicalPath, KVVersionV1.String(), nil

	case KVVersionV2:
		_, err = client.Secrets.KvV2Read(ctx, path, vcg.WithMountPath(mount))
		if err != nil {
			return secretType, canonicalPath, KVVersionV2.String(), toPkgErr(err)
		}

		_, err := client.Secrets.KvV2Write(ctx, path, vcgSchema.KvV2WriteRequest{Data: payload}, vcg.WithMountPath(mount))
		if err != nil {
			return secretType, canonicalPath, KVVersionV2.String(), toPkgErr(err)
		}
		return secretType, canonicalPath, KVVersionV2.String(), nil
	}

	return secretType, "", "", errors.New("unknown kv engine version")
}
