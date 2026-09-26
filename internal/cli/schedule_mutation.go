package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newScheduleCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg string
	var yes bool
	c := &cobra.Command{Use: "create <name>", Short: "Create a schedule", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		body, err := LoadBody(bodyArg)
		if err != nil {
			return err
		}
		if err := setScheduleBodyName(body, name); err != nil {
			return err
		}
		profiles, err := resolveTargetProfiles(cmd, d.Config)
		if err != nil {
			return err
		}
		if len(profiles) == 1 {
			result, err := scheduleSvc(d, cat).Create(cmd.Context(), profiles[0], name, body, !yes)
			if err != nil {
				return err
			}
			return printObjectMutation(cmd, result)
		}
		op := func(ctx context.Context, profile string, preflight bool) (any, error) {
			return scheduleSvc(d, cat).Create(ctx, profile, name, body, preflight || !yes)
		}
		return printFanout(cmd, svc.Run(cmd.Context(), "schedule_create", profiles, op, !yes))
	}}
	c.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(c)
	_ = c.MarkFlagRequired("body")
	return c
}

func newScheduleUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg, expectedHash string
	var yes, ignoreHash bool
	c := &cobra.Command{Use: "update <name>", Short: "Update a schedule", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if expectedHash == "" && !ignoreHash {
			return fmt.Errorf("%w: expected-diff-hash is required for update (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
		}
		body, err := LoadBody(bodyArg)
		if err != nil {
			return err
		}
		if err := setScheduleBodyName(body, name); err != nil {
			return err
		}
		profiles, err := resolveTargetProfiles(cmd, d.Config)
		if err != nil {
			return err
		}
		if len(profiles) == 1 {
			result, err := scheduleSvc(d, cat).Update(cmd.Context(), profiles[0], name, body, expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			return printObjectMutation(cmd, result)
		}
		op := func(ctx context.Context, profile string, preflight bool) (any, error) {
			return scheduleSvc(d, cat).Update(ctx, profile, name, body, expectedHash, ignoreHash, preflight || !yes)
		}
		return printFanout(cmd, svc.Run(cmd.Context(), "schedule_update", profiles, op, !yes))
	}}
	c.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior schedule show / object get; required for update and delete, including dry-run, unless --ignore-diff-hash")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(c)
	_ = c.MarkFlagRequired("body")
	return c
}

func newScheduleDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var expectedHash string
	var yes, ignoreHash bool
	c := &cobra.Command{Use: "delete <name>", Short: "Delete a schedule", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if expectedHash == "" && !ignoreHash {
			return fmt.Errorf("%w: expected-diff-hash is required for delete (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
		}
		profiles, err := resolveTargetProfiles(cmd, d.Config)
		if err != nil {
			return err
		}
		if len(profiles) == 1 {
			result, err := scheduleSvc(d, cat).Delete(cmd.Context(), profiles[0], name, expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			return printObjectMutation(cmd, result)
		}
		op := func(ctx context.Context, profile string, preflight bool) (any, error) {
			return scheduleSvc(d, cat).Delete(ctx, profile, name, expectedHash, ignoreHash, preflight || !yes)
		}
		return printFanout(cmd, svc.Run(cmd.Context(), "schedule_delete", profiles, op, !yes))
	}}
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior schedule show / object get; required for update and delete, including dry-run, unless --ignore-diff-hash")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(c)
	return c
}

func setScheduleBodyName(body map[string]any, name string) error {
	if value, exists := body["Name"]; exists {
		bodyName, ok := value.(string)
		if !ok || strings.TrimSpace(bodyName) == "" {
			return fmt.Errorf("%w: body Name must be a non-empty string", sophos.ErrInvalidRequest)
		}
		if bodyName != name {
			return fmt.Errorf("%w: body Name %q does not match positional arg %q", sophos.ErrInvalidRequest, bodyName, name)
		}
	}
	body["Name"] = name
	return nil
}
