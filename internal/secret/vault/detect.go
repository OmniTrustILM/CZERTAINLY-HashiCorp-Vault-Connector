package vault

import (
	"context"
	"fmt"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"

	vcg "github.com/hashicorp/vault-client-go"
	"github.com/stretchr/objx"

	"go.uber.org/zap"
)

const (
	mountInfoTypeKVString = "kv"
)

func DetectKVVersion(ctx context.Context, client *vcg.Client, mount string) (KVVersion, error) {
	mounts, err := client.System.InternalUiListEnabledVisibleMounts(ctx)
	if err != nil {
		return KVVersionV1, fmt.Errorf("`InternalUiListEnabledVisibleMounts()` failed: %w", toPkgErr(err))
	}

	log := logger.Get()
	// if there are any warnings on the response, log them
	if len(mounts.Warnings) > 0 {
		fields := make([]zap.Field, 0, len(mounts.Warnings))
		for i, v := range mounts.Warnings {
			fields = append(fields, zap.String(fmt.Sprintf("warning-%d", i), v))
		}
		log.Warn("Calling `InternalUiListEnabledVisibleMounts()` returned a response with warnings.", fields...)
	}

	for engineName, engineData := range mounts.Data.Secret {
		if mount != engineName {
			continue
		}

		o := objx.New(engineData)
		if !o.Get("type").IsStr() {
			log.Warn("Unexpected mount info structure, expected type of key `type` is string.", zap.String("mount", engineName), zap.Any("info", engineData))
			continue
		}

		if o.Get("type").Str() != mountInfoTypeKVString {
			continue
		}

		if o.Get("options.version").Str() == "2" {
			return KVVersionV2, nil
		} else {
			return KVVersionV1, nil
		}
	}
	return KVVersionV1, ErrNotFound
}
