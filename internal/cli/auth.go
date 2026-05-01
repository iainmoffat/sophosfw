package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newAuthCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Authentication and profile management"}
	cmd.AddCommand(
		newAuthLoginCmd(d),
		newAuthStatusCmd(d),
		newAuthTestCmd(d),
		newAuthLogoutCmd(d),
		newAuthProfileCmd(d),
	)
	return cmd
}

func newAuthLoginCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Validate credentials against the firewall and persist them",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			username, password, err := promptCredentials(cmd)
			if err != nil {
				return err
			}
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			if err := a.Login(cmd.Context(), profile, username, password); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
}

func promptCredentials(cmd *cobra.Command) (string, string, error) {
	if u := os.Getenv("SOPHOSFW_USERNAME"); u != "" {
		return u, os.Getenv("SOPHOSFW_PASSWORD"), nil
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Username: ")
	r := bufio.NewReader(os.Stdin)
	username, err := r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	username = strings.TrimSpace(username)

	fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", "", err
	}
	fmt.Fprintln(cmd.ErrOrStderr())
	return username, string(pw), nil
}

func newAuthStatusCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current profile and whether credentials are stored",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			st, err := a.Status(profile)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.authStatus", map[string]any{
					"profile":            st.Profile,
					"url":                st.URL,
					"loggedIn":           st.LoggedIn,
					"credentialsBackend": st.CredentialsBackend,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "profile: %s\nurl: %s\nloggedIn: %t\nbackend: %s\n",
				st.Profile, st.URL, st.LoggedIn, st.CredentialsBackend)
			return nil
		},
	}
}

func newAuthTestCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Test connectivity and stored credentials against the firewall",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			r, err := a.Test(cmd.Context(), profile)
			if err != nil {
				_ = render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.connectionTest", map[string]any{
					"profile":      r.Profile,
					"ok":           false,
					"latencyMs":    r.LatencyMs,
					"apiReachable": r.APIReachable,
					"authOk":       r.AuthOK,
					"error":        r.Error,
				})
				return err
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.connectionTest", map[string]any{
				"profile":      r.Profile,
				"ok":           r.OK,
				"latencyMs":    r.LatencyMs,
				"apiReachable": r.APIReachable,
				"authOk":       r.AuthOK,
			})
		},
	}
}

func newAuthLogoutCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete stored credentials for the current/selected profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			return a.Logout(profile)
		},
	}
}

func newAuthProfileCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "profile", Short: "Manage firewall profiles"}
	cmd.AddCommand(
		newProfileAddCmd(d),
		newProfileListCmd(d),
		newProfileUseCmd(d),
		newProfileRemoveCmd(d),
	)
	return cmd
}

func newProfileAddCmd(d RootDeps) *cobra.Command {
	var url string
	var readOnly bool
	c := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new firewall profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			return ps.Add(args[0], url, readOnly)
		},
	}
	c.Flags().StringVar(&url, "url", "", "firewall base URL (e.g. https://fw.example.com:4444)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "create profile in read-only mode")
	_ = c.MarkFlagRequired("url")
	return c
}

func newProfileListCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all profiles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			list := ps.List()
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				profiles := make([]map[string]any, 0, len(list))
				for _, p := range list {
					profiles = append(profiles, map[string]any{
						"name":     p.Name,
						"url":      p.URL,
						"readOnly": p.ReadOnly,
						"current":  p.Current,
					})
				}
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.profileList", map[string]any{
					"current":  d.Config.CurrentProfile,
					"profiles": profiles,
				})
			}
			for _, p := range list {
				marker := "  "
				if p.Current {
					marker = "* "
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s%s\t%s\n", marker, p.Name, p.URL)
			}
			return nil
		},
	}
}

func newProfileUseCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Switch the current profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			return ps.Use(args[0])
		},
	}
}

func newProfileRemoveCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a profile and its stored credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			return ps.Remove(args[0])
		},
	}
}
