package authority

import (
	"errors"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
)

// fakeAuthorityRepository is an in-memory stand-in for *db.AuthorityRepository
// satisfying the authorityRepository interface. Each method records its call
// and returns a pre-configured result, so tests can drive findAuthority and
// the service methods in this package without a live database.
type fakeAuthorityRepository struct {
	findByUUID      *db.AuthorityInstance
	findByUUIDErr   error
	findByUUIDCalls []string

	findByName      *db.AuthorityInstance
	findByNameErr   error
	findByNameCalls []string

	createErr   error
	createCalls []db.AuthorityInstance

	updateErr   error
	updateCalls []db.AuthorityInstance

	deleteErr   error
	deleteCalls []db.AuthorityInstance

	list    []*db.AuthorityInstance
	listErr error
}

var _ authorityRepository = (*fakeAuthorityRepository)(nil)

func (f *fakeAuthorityRepository) FindAuthorityInstanceByUUID(uuid string) (*db.AuthorityInstance, error) {
	f.findByUUIDCalls = append(f.findByUUIDCalls, uuid)
	if f.findByUUIDErr != nil {
		return nil, f.findByUUIDErr
	}
	if f.findByUUID == nil {
		return nil, errors.New("fakeAuthorityRepository: FindAuthorityInstanceByUUID not configured for this test")
	}
	return f.findByUUID, nil
}

func (f *fakeAuthorityRepository) FindAuthorityInstanceByName(name string) (*db.AuthorityInstance, error) {
	f.findByNameCalls = append(f.findByNameCalls, name)
	if f.findByNameErr != nil {
		return nil, f.findByNameErr
	}
	if f.findByName == nil {
		return nil, errors.New("fakeAuthorityRepository: FindAuthorityInstanceByName not configured for this test")
	}
	return f.findByName, nil
}

func (f *fakeAuthorityRepository) CreateAuthorityInstance(authority *db.AuthorityInstance) error {
	f.createCalls = append(f.createCalls, *authority)
	return f.createErr
}

func (f *fakeAuthorityRepository) UpdateAuthorityInstance(authority *db.AuthorityInstance) error {
	f.updateCalls = append(f.updateCalls, *authority)
	return f.updateErr
}

func (f *fakeAuthorityRepository) DeleteAuthorityInstance(authority *db.AuthorityInstance) error {
	f.deleteCalls = append(f.deleteCalls, *authority)
	return f.deleteErr
}

func (f *fakeAuthorityRepository) ListAuthorityInstances() ([]*db.AuthorityInstance, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.list, nil
}

// unreachableVaultURL is a syntactically valid placeholder Vault address used
// by tests that need vault.GetClient to fail. It is never actually dialed:
// for the JWT/OIDC and Kubernetes credential types (the ones these tests
// use), vault.GetClient reads a service-account token file that does not
// exist on a test machine before it would attempt any network call, so the
// login fails deterministically and instantly regardless of this address.
const unreachableVaultURL = "https://vault.example.invalid"
