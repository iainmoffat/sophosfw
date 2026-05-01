package svc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// AuthSvc owns login/status/test/logout.
type AuthSvc struct {
	Config    *config.Config
	Creds     creds.Store
	BaseDir   string
	NewClient ClientFactory
}

// AuthStatus is the render-friendly view of `auth status`.
type AuthStatus struct {
	Profile            string
	URL                string
	LoggedIn           bool
	CredentialsBackend string
}

// ConnectionResult is the render-friendly view of `auth test`.
type ConnectionResult struct {
	Profile      string
	OK           bool
	LatencyMs    int64
	APIReachable bool
	AuthOK       bool
	Error        string
}

// Login validates credentials by calling the firewall, then persists them
// only on success.
func (a *AuthSvc) Login(ctx context.Context, profileName, username, password string) error {
	p, _, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return err
	}
	c := a.NewClient(p, creds.Credentials{Username: username, Password: password})
	if _, err := c.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}}}); err != nil {
		return err
	}
	return a.Creds.Save(profileName, creds.Credentials{Username: username, Password: password})
}

// Status reports whether credentials are stored for the profile.
func (a *AuthSvc) Status(profileName string) (AuthStatus, error) {
	p, name, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return AuthStatus{}, err
	}
	st := AuthStatus{
		Profile:            name,
		URL:                p.URL,
		CredentialsBackend: a.Creds.Backend(),
	}
	if _, err := a.Creds.Load(name); err == nil {
		st.LoggedIn = true
	} else if !errors.Is(err, creds.ErrNotFound) {
		return st, err
	}
	return st, nil
}

// Test performs a minimal Get to verify the firewall is reachable and the
// stored credentials still authenticate.
func (a *AuthSvc) Test(ctx context.Context, profileName string) (ConnectionResult, error) {
	p, name, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return ConnectionResult{}, err
	}
	c, err := a.Creds.Load(name)
	if err != nil {
		return ConnectionResult{Profile: name, Error: "no stored credentials"}, fmt.Errorf("auth test: %w", err)
	}
	cl := a.NewClient(p, c)
	start := time.Now()
	_, err = cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}}})
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return ConnectionResult{
			Profile:   name,
			OK:        false,
			LatencyMs: latency,
			AuthOK:    !errors.Is(err, sophos.ErrAuthFailed),
			APIReachable: !isNetworkError(err),
			Error:     err.Error(),
		}, err
	}
	return ConnectionResult{
		Profile:      name,
		OK:           true,
		LatencyMs:    latency,
		APIReachable: true,
		AuthOK:       true,
	}, nil
}

// Logout clears stored credentials for the profile.
func (a *AuthSvc) Logout(profileName string) error {
	_, name, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return err
	}
	if err := a.Creds.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
		return err
	}
	return nil
}

func isNetworkError(err error) bool {
	// Heuristic: anything not auth-failed and not a Sophos status error is
	// likely transport.
	if errors.Is(err, sophos.ErrAuthFailed) {
		return false
	}
	var se *sophos.StatusError
	return !errors.As(err, &se)
}
