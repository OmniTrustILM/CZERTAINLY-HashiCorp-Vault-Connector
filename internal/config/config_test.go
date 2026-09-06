package config

import "testing"

// setMandatory sets the three variables config.Get treats as required, so a
// test can exercise the defaulting paths without tripping its Fatal calls.
func setMandatory(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_USER", "user")
	t.Setenv("DATABASE_PASSWORD", "password")
	t.Setenv("DATABASE_NAME", "hvault")
}

func TestGetAppliesDefaultsWhenOptionalVarsAreUnset(t *testing.T) {
	setMandatory(t)
	t.Setenv("SERVER_PORT", "")
	t.Setenv("DATABASE_HOST", "")
	t.Setenv("DATABASE_PORT", "")
	t.Setenv("DATABASE_SCHEMA", "")
	t.Setenv("DATABASE_SSL_MODE", "")

	got := Get()

	for _, tc := range []struct{ name, got, want string }{
		{"server port", got.Server.Port, "8080"},
		{"database host", got.Database.Host, "localhost"},
		{"database port", got.Database.Port, "5432"},
		{"database schema", got.Database.Schema, "hvault"},
		{"database ssl mode", got.Database.SslMode, "require"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestGetPrefersEnvironmentOverDefaults(t *testing.T) {
	setMandatory(t)
	t.Setenv("SERVER_PORT", "9090")
	t.Setenv("DATABASE_HOST", "db.internal")
	t.Setenv("DATABASE_PORT", "6543")
	t.Setenv("DATABASE_SCHEMA", "custom")
	t.Setenv("DATABASE_SSL_MODE", "disable")

	got := Get()

	for _, tc := range []struct{ name, got, want string }{
		{"server port", got.Server.Port, "9090"},
		{"database host", got.Database.Host, "db.internal"},
		{"database port", got.Database.Port, "6543"},
		{"database schema", got.Database.Schema, "custom"},
		{"database ssl mode", got.Database.SslMode, "disable"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestGetCarriesCredentialsThrough(t *testing.T) {
	setMandatory(t)
	t.Setenv("DATABASE_PROPS", "sslrootcert=/certs/ca.pem")

	got := Get()

	if got.Database.Username != "user" {
		t.Errorf("username: got %q, want %q", got.Database.Username, "user")
	}
	if got.Database.Password != "password" {
		t.Errorf("password: got %q, want %q", got.Database.Password, "password")
	}
	if got.Database.Props != "sslrootcert=/certs/ca.pem" {
		t.Errorf("props: got %q, want %q", got.Database.Props, "sslrootcert=/certs/ca.pem")
	}
}
