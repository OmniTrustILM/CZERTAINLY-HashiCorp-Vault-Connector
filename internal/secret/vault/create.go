package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"

	vcg "github.com/hashicorp/vault-client-go"
	vcgSchema "github.com/hashicorp/vault-client-go/schema"
)

func (m *Manager) Create(ctx context.Context, client *vcg.Client, mount, path string, secret sm.SecretContent) (sm.SecretType, string, string, error) {
	createLock := lockRef(mount, path)
	m.locks.Lock(createLock)
	defer m.locks.Unlock(createLock)

	v, payload, secretType, err := commonCreateUpdate(ctx,
		client,
		mount,
		secret,
	)
	if err != nil {
		return secretType, "", "", err
	}

	canonicalPath := fmt.Sprintf("%s%s", mount, path)

	switch v {
	case KVVersionV1:
		_, err = client.Secrets.KvV1Read(ctx, path, vcg.WithMountPath(mount))
		switch {
		case err == nil:
			return sm.SecretType(""), canonicalPath, KVVersionV1.String(), ErrAlreadyExists

		case !vcg.IsErrorStatus(err, http.StatusNotFound):
			return secretType, canonicalPath, KVVersionV1.String(), toPkgErr(err)
		}

		_, err := client.Secrets.KvV1Write(ctx, path, payload, vcg.WithMountPath(mount))
		if err != nil {
			return secretType, canonicalPath, KVVersionV1.String(), toPkgErr(err)
		}
		return secretType, canonicalPath, KVVersionV1.String(), nil

	case KVVersionV2:
		_, err := client.Secrets.KvV2Write(ctx, path, vcgSchema.KvV2WriteRequest{
			Data: payload,
			Options: map[string]any{
				"cas": 0,
			},
		}, vcg.WithMountPath(mount))
		if err != nil {
			if vcg.IsErrorStatus(err, http.StatusBadRequest) {
				return secretType, canonicalPath, KVVersionV2.String(), ErrAlreadyExists
			}
			return secretType, canonicalPath, KVVersionV2.String(), toPkgErr(err)
		}
		return secretType, canonicalPath, KVVersionV2.String(), nil

	}

	return secretType, "", "", errors.New("unknown kv engine version")
}
