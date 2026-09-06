package vault

import (
	"context"
	"fmt"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"os"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

var log = logger.Get()

const DEFAULT_K8S_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
const DEFAULT_VAULT_ROLE = "vault-connector-role"
const DEFAULT_KUBERNETES_MOUNT_PATH = "kubernetes"
const DEFAULT_JWT_MOUNT_PATH = "jwt"
const DEFAULT_APPROLE_MOUNT_PATH = "approle"

type LoginMethod interface {
	Login(client *vault.Client) (*vault.Client, error)
}

type AppRoleLogin struct {
	RoleId    string
	SecretId  string
	MountPath string
}

func (l AppRoleLogin) Login(client *vault.Client) (*vault.Client, error) {
	ctx := context.Background()
	var mountPath string
	if l.MountPath != "" {
		mountPath = l.MountPath
	} else {
		mountPath = DEFAULT_APPROLE_MOUNT_PATH
	}

	resp, err := client.Auth.AppRoleLogin(
		ctx,
		schema.AppRoleLoginRequest{
			RoleId:   l.RoleId,
			SecretId: l.SecretId,
		},
		vault.WithMountPath(mountPath),
	)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		log.Error(err.Error())
		return nil, err
	}
	return client, nil
}

type LoginWithToken struct {
	VaultRole string
	MountPath string
}

func (l LoginWithToken) Login(client *vault.Client) (*vault.Client, error) {
	ctx := context.Background()
	token, err := os.ReadFile(DEFAULT_K8S_TOKEN_PATH)
	var mountPath, vaultRole string
	if l.MountPath != "" {
		mountPath = l.MountPath
	} else {
		mountPath = DEFAULT_JWT_MOUNT_PATH
	}

	if l.VaultRole != "" {
		vaultRole = l.VaultRole
	} else {
		vaultRole = DEFAULT_VAULT_ROLE

	}
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	jwt := string(token)
	authInfo, err := client.Auth.JwtLogin(ctx, schema.JwtLoginRequest{
		Jwt:  jwt,
		Role: vaultRole,
	}, vault.WithMountPath(mountPath))
	if err != nil {
		return nil, fmt.Errorf("unable to log in with JWT auth: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after JWT login")
	}

	err = client.SetToken(authInfo.Auth.ClientToken)
	if err != nil {
		return nil, err
	}
	return client, nil
}

type LoginWithK8sToken struct {
	VaultRole string
	MountPath string
}

func (l LoginWithK8sToken) Login(client *vault.Client) (*vault.Client, error) {
	ctx := context.Background()
	token, err := os.ReadFile(DEFAULT_K8S_TOKEN_PATH) // Replace with your actual file path
	var mountPath, vaultRole string
	if l.MountPath != "" {
		mountPath = l.MountPath
	} else {
		mountPath = DEFAULT_KUBERNETES_MOUNT_PATH
	}

	if l.VaultRole != "" {
		vaultRole = l.VaultRole
	} else {
		vaultRole = DEFAULT_VAULT_ROLE

	}
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	jwt := string(token)
	authInfo, err := client.Auth.KubernetesLogin(ctx, schema.KubernetesLoginRequest{
		Jwt:  jwt,
		Role: vaultRole,
	}, vault.WithMountPath(mountPath))
	if err != nil {
		return nil, fmt.Errorf("unable to log in with Kubernetes auth: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after K8s login")
	}

	err = client.SetToken(authInfo.Auth.ClientToken)
	if err != nil {
		return nil, err
	}
	return client, nil
}
func getLoginMethod(authority db.AuthorityInstance) LoginMethod {
	switch authority.CredentialType {
	case model.JWTOIDC_CRED:
		return LoginWithToken{
			VaultRole: authority.VaultRole,
			MountPath: authority.MountPath,
		}
	case model.KUBERNETES_CRED:
		return LoginWithK8sToken{
			VaultRole: authority.VaultRole,
			MountPath: authority.MountPath,
		}
	case model.APPROLE_CRED:
		return AppRoleLogin{
			RoleId:    authority.RoleId,
			SecretId:  authority.RoleSecret,
			MountPath: authority.MountPath,
		}

	}
	return nil
}

func GetClient(authority db.AuthorityInstance) (*vault.Client, error) {
	client, err := vault.New(
		vault.WithAddress(authority.URL),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Error(err.Error())
	}
	return getLoginMethod(authority).Login(client)
}
