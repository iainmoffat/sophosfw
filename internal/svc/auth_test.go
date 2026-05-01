package svc

import (
	"context"
	"errors"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeClient struct {
	doErr error
	calls int
}

func (f *fakeClient) Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error) {
	f.calls++
	if f.doErr != nil {
		return nil, f.doErr
	}
	return &sophos.Response{LoginOK: true, LoginStatus: "Authentication Successful"}, nil
}

func (f *fakeClient) DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error) {
	f.calls++
	if f.doErr != nil {
		return nil, f.doErr
	}
	return &sophos.Response{LoginOK: true, LoginStatus: "Authentication Successful"}, nil
}

func newAuthSvc(t *testing.T, fc *fakeClient) (*AuthSvc, *ProfileSvc) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.New()
	store := creds.NewFileStore(dir)
	ps := &ProfileSvc{Config: cfg, Creds: store, BaseDir: dir}
	require.NoError(t, ps.Add("home", "https://x:4444", false))
	auth := &AuthSvc{
		Config:  cfg,
		Creds:   store,
		BaseDir: dir,
		NewClient: func(p config.Profile, c creds.Credentials) Client {
			return fc
		},
	}
	return auth, ps
}

func TestAuthSvc_Login_StoresCredsOnSuccess(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "admin", "secret"))

	got, err := a.Creds.Load("home")
	require.NoError(t, err)
	require.Equal(t, "admin", got.Username)
}

func TestAuthSvc_Login_DoesNotStoreOnAuthFailure(t *testing.T) {
	fc := &fakeClient{doErr: sophos.ErrAuthFailed}
	a, _ := newAuthSvc(t, fc)
	err := a.Login(context.Background(), "home", "admin", "wrong")
	require.ErrorIs(t, err, sophos.ErrAuthFailed)
	_, err = a.Creds.Load("home")
	require.ErrorIs(t, err, creds.ErrNotFound)
}

func TestAuthSvc_Status_NotLoggedInWhenNoCreds(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	st, err := a.Status("home")
	require.NoError(t, err)
	require.False(t, st.LoggedIn)
}

func TestAuthSvc_Status_LoggedInAfterLogin(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "u", "p"))
	st, err := a.Status("home")
	require.NoError(t, err)
	require.True(t, st.LoggedIn)
}

func TestAuthSvc_Test_RoundTrips(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "u", "p"))
	r, err := a.Test(context.Background(), "home")
	require.NoError(t, err)
	require.True(t, r.OK)
}

func TestAuthSvc_Logout_DeletesCreds(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "u", "p"))
	require.NoError(t, a.Logout("home"))
	_, err := a.Creds.Load("home")
	require.True(t, errors.Is(err, creds.ErrNotFound))
}
