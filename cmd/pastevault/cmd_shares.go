package main

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

func runList(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("list", "pastevault list [--type paste|files] [--status S] [--limit N] [flags]")
	shareType := fs.String("type", "", "Only pastes (paste) or file shares (files)")
	status := fs.String("status", "", "Only shares with this status: active, burned, expired, deleted, uploading or abandoned")
	limit := fs.Int("limit", 50, "Maximum number of shares (1-200)")
	cursor := fs.String("cursor", "", "Continue from the next_cursor of a previous page")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("list does not take positional arguments")
	}

	query := pv.AccountSharesQuery{Status: strings.ToLower(*status), Limit: *limit, Cursor: *cursor}
	switch strings.ToLower(*shareType) {
	case "":
	case "paste", "pastes":
		query.ShareType = "paste"
	case "files", "file", "file_share", "file-share":
		query.ShareType = "file_share"
	default:
		return pv.UsageError("--type must be paste or files")
	}
	if *limit < 1 || *limit > 200 {
		return pv.UsageError("--limit must be between 1 and 200")
	}

	client, _, _, err := accountClient(ctx, common, featureAccounts)
	if err != nil {
		return err
	}
	response, err := client.ListAccountShares(ctx, query)
	if err != nil {
		return err
	}
	if response.Shares == nil {
		response.Shares = []pv.AccountShare{}
	}
	for index := range response.Shares {
		response.Shares[index].Status = effectiveStatus(response.Shares[index])
	}

	if out.json() {
		return out.emitJSON(response)
	}

	if len(response.Shares) == 0 {
		out.infof("No shares found.")
		return nil
	}

	table := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	if !common.quiet {
		fmt.Fprintln(table, "ID\tTYPE\tSLUG\tSTATUS\tVIEWS\tEXPIRES\tCREATED")
	}
	for _, share := range response.Shares {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			share.ID, displayShareType(share.ShareType), share.Slug, share.Status,
			formatViews(share.ViewCount, share.MaxViews), formatOptionalTime(share.ExpiresAt, "never"), formatTime(share.CreatedAt))
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if response.NextCursor != nil && !common.quiet {
		out.infof("More shares: pastevault list --cursor %s", *response.NextCursor)
	}

	return nil
}

func runRevoke(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("revoke", "pastevault revoke [flags] <slug | url | id>...")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) == 0 {
		return pv.UsageError("name at least one share to revoke (slug, URL or id from pastevault list)")
	}

	client, _, _, err := accountClient(ctx, common, featureAccounts)
	if err != nil {
		return err
	}

	type revokeResult struct {
		Ref    string `json:"ref"`
		ID     string `json:"id,omitempty"`
		Slug   string `json:"slug,omitempty"`
		Status string `json:"status,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	results := make([]revokeResult, 0, len(positional))
	var firstErr error

	for _, arg := range positional {
		result := revokeResult{Ref: redactRef(arg)}
		share, err := findOwnedShare(ctx, client, common, arg)
		if err == nil {
			var response pv.RevokeAccountShareResponse
			response, err = client.RevokeAccountShare(ctx, share.ID)
			if err == nil {
				result.ID, result.Slug, result.Status = response.Share.ID, response.Share.Slug, response.Share.Status
			}
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			result.Error = pv.Classify(err).Error()
			if !out.json() {
				fmt.Fprintf(a.stderr, "Error: %s: %s\n", result.Ref, result.Error)
			}
		} else if !out.json() {
			out.printf("Revoked %s (%s)\n", result.Slug, result.ID)
		}
		results = append(results, result)
	}

	if out.json() {
		if firstErr != nil {
			// The error object carries the exit code; per-share results go to
			// stderr so stdout still holds one JSON object.
			for _, result := range results {
				if result.Error == "" {
					fmt.Fprintf(a.stderr, "Revoked %s (%s)\n", result.Slug, result.ID)
				}
			}
			return firstErr
		}
		return out.emitJSON(map[string]any{"revoked": results})
	}

	return firstErr
}

// ownedShareIDScanLimit caps how many shares an id lookup pages through.
const ownedShareIDScanLimit = 1000

// findOwnedShare resolves a slug, share URL, pv://share handle or owned-share
// id to one of the account's shares.
func findOwnedShare(ctx context.Context, client *pv.Client, common *commonFlags, arg string) (pv.AccountShare, error) {
	ref, refErr := pv.ParseShareReference(arg, common.server, pv.ResolvePublicBaseURL(common.server))
	if refErr == nil {
		// A link to another server names a share this account can't own here.
		if !pv.SameServer(ref.Server, common.server) {
			return pv.AccountShare{}, pv.UsageError("%s is a share on %s, not on %s; pass --server %s", redactRef(arg), ref.Server, client.BaseURL(), ref.Server)
		}

		response, err := client.ListAccountShares(ctx, pv.AccountSharesQuery{Slug: ref.Slug, Limit: 10})
		if err != nil {
			return pv.AccountShare{}, err
		}
		// Servers without the slug filter return every share: match it here.
		for _, share := range response.Shares {
			if share.Slug == ref.Slug && (ref.Kind == pv.ShareKindUnknown || share.ShareType == string(ref.Kind)) {
				return share, nil
			}
		}
	}

	// Not a slug of ours: it may be an owned-share id from "list". Page
	// through the newest shares, up to a bound.
	if pv.IsValidSlug(arg) {
		cursor := ""
		for scanned := 0; scanned < ownedShareIDScanLimit; {
			response, err := client.ListAccountShares(ctx, pv.AccountSharesQuery{Limit: 200, Cursor: cursor})
			if err != nil {
				return pv.AccountShare{}, err
			}
			for _, share := range response.Shares {
				if share.ID == arg {
					return share, nil
				}
			}
			scanned += len(response.Shares)
			if response.NextCursor == nil || len(response.Shares) == 0 {
				break
			}
			cursor = *response.NextCursor
		}
	}

	if refErr != nil && !pv.IsValidSlug(arg) {
		return pv.AccountShare{}, refErr
	}

	return pv.AccountShare{}, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no share %s among the shares of this account", redactRef(arg))
}

// statusOutput is the --json result of status.
type statusOutput struct {
	pv.AccountShare
	ViewsRemaining *int            `json:"views_remaining"`
	Events         []pv.AuditEvent `json:"events"`
	WaitedFor      string          `json:"waited_for,omitempty"`
}

func runStatus(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("status", "pastevault status [flags] <slug | url | id>")
	waitFor := fs.String("wait", "", "Wait until the share is viewed or burned (read receipt)")
	timeout := fs.String("timeout", "10m", "How long --wait waits (exit 9 when it runs out)")
	interval := fs.String("interval", "2s", "How often --wait polls")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one share (slug, URL or id) is required")
	}

	condition := strings.ToLower(*waitFor)
	if condition != "" && condition != "viewed" && condition != "burned" {
		return pv.UsageError("--wait must be viewed or burned")
	}
	waitTimeout, err := pv.ParseWaitDuration("--timeout", *timeout)
	if err != nil {
		return err
	}
	pollInterval, err := pv.ParseWaitDuration("--interval", *interval)
	if err != nil {
		return err
	}

	client, _, capabilities, err := accountClient(ctx, common, featureAccounts)
	if err != nil {
		return err
	}

	share, err := findOwnedShare(ctx, client, common, positional[0])
	if err != nil {
		return err
	}

	if condition == "burned" && share.MaxViews == nil && !share.BurnAfterRead {
		return pv.UsageError("share %s has no view limit, so it never burns; use --wait viewed", share.Slug)
	}
	if condition != "" {
		share, err = waitForShare(ctx, client, share, condition, waitTimeout, pollInterval, out)
		if err != nil {
			return err
		}
	}

	// Servers without the audit log have no per-share events.
	events := pv.ListShareEventsResponse{Events: []pv.AuditEvent{}}
	if capabilities.Features.Audit {
		if events, err = client.ListShareEvents(ctx, share.ID); err != nil {
			return err
		}
		if events.Events == nil {
			events.Events = []pv.AuditEvent{}
		}
	}

	result := statusOutput{AccountShare: share, Events: events.Events, WaitedFor: condition}
	result.Status = effectiveStatus(share)
	if share.MaxViews != nil {
		remaining := max(*share.MaxViews-share.ViewCount, 0)
		result.ViewsRemaining = &remaining
	}

	if out.json() {
		return out.emitJSON(result)
	}

	out.printf("%s %s %s\n", result.Slug, displayShareType(result.ShareType), result.Status)
	if common.quiet {
		return nil
	}
	out.printf("views    %s\n", formatViews(result.ViewCount, result.MaxViews))
	out.printf("expires  %s\n", formatOptionalTime(result.ExpiresAt, "never"))
	if result.LastViewedAt != nil {
		out.printf("viewed   %s\n", formatOptionalTime(result.LastViewedAt, ""))
	}
	if len(result.Events) > 0 {
		out.printf("\n")
		printEvents(a, result.Events)
	}

	return nil
}

// waitForShare polls until the share is viewed (or burned). A share that
// expires or is revoked first ends the wait with exit 5; running out of time
// is exit 9.
func waitForShare(ctx context.Context, client *pv.Client, share pv.AccountShare, condition string, timeout, interval time.Duration, out *output) (pv.AccountShare, error) {
	deadline := time.Now().Add(timeout)
	out.infof("Waiting up to %s for %s to be %s...", timeout, share.Slug, condition)

	for {
		status := effectiveStatus(share)
		if condition == "viewed" && (share.ViewCount > 0 || status == "burned") {
			return share, nil
		}
		if condition == "burned" && status == "burned" {
			return share, nil
		}
		switch status {
		case "expired", "deleted", "abandoned":
			return share, pv.NewError(pv.ExitGone, pv.CodeGone, "share %s is %s and will not be %s", share.Slug, status, condition)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return share, pv.NewError(pv.ExitTimeout, pv.CodeTimeout, "share %s was not %s within %s", share.Slug, condition, timeout)
		}

		timer := time.NewTimer(min(interval, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return share, ctx.Err()
		case <-timer.C:
		}

		response, err := client.ListAccountShares(ctx, pv.AccountSharesQuery{Slug: share.Slug, Limit: 10})
		if err != nil {
			return share, err
		}
		found := false
		for _, candidate := range response.Shares {
			if candidate.ID == share.ID {
				share, found = candidate, true
			}
		}
		if !found {
			return share, pv.NewError(pv.ExitGone, pv.CodeGone, "share %s is no longer listed", share.Slug)
		}
	}
}

// effectiveStatus reports an active share past its expiry as expired; the
// server marks it lazily or on its cleanup schedule.
func effectiveStatus(share pv.AccountShare) string {
	if share.Status == "active" && share.ExpiresAt != nil {
		if expiresAt, err := time.Parse(time.RFC3339Nano, *share.ExpiresAt); err == nil && time.Now().After(expiresAt) {
			return "expired"
		}
	}

	return share.Status
}

func runAudit(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("audit", "pastevault audit [--since 24h] [--event E] [--limit 50] [flags]")
	since := fs.String("since", "", "Only events after this: 15m, 24h, 7d, or an RFC 3339 time")
	event := fs.String("event", "", "Only this event, e.g. share.viewed")
	limit := fs.Int("limit", 50, "Maximum number of events (1-200)")
	cursor := fs.String("cursor", "", "Continue from the next_cursor of a previous page")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("audit does not take positional arguments")
	}
	if *since != "" {
		if err := pv.ValidateSince(*since); err != nil {
			return err
		}
	}
	if *limit < 1 || *limit > 200 {
		return pv.UsageError("--limit must be between 1 and 200")
	}

	client, _, _, err := accountClient(ctx, common, featureAudit)
	if err != nil {
		return err
	}
	response, err := client.ListAuditEvents(ctx, pv.AuditQuery{Since: *since, Event: *event, Limit: *limit, Cursor: *cursor})
	if err != nil {
		return err
	}
	if response.Events == nil {
		response.Events = []pv.AuditEvent{}
	}

	if out.json() {
		return out.emitJSON(response)
	}
	if len(response.Events) == 0 {
		out.infof("No events.")
		return nil
	}
	printEvents(a, response.Events)
	if response.NextCursor != nil && !common.quiet {
		out.infof("More events: pastevault audit --cursor %s", *response.NextCursor)
	}

	return nil
}

func printEvents(a *app, events []pv.AuditEvent) {
	table := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "TIME\tEVENT\tSUBJECT\tACTOR\tCLIENT")
	for _, event := range events {
		subject := event.SubjectType
		if event.Slug != nil {
			subject = *event.Slug
		}
		actor := event.ActorKind
		if event.ActorAgent != nil && event.ActorAgent.Name != nil {
			actor += " (" + *event.ActorAgent.Name + ")"
		}
		client := "-"
		if event.Client != nil {
			client = *event.Client
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", formatTime(event.CreatedAt), event.Event, subject, actor, client)
	}
	_ = table.Flush()
}

func displayShareType(shareType string) string {
	if shareType == "file_share" {
		return "files"
	}

	return shareType
}

func formatViews(viewCount int, maxViews *int) string {
	if maxViews == nil {
		return fmt.Sprintf("%d", viewCount)
	}

	return fmt.Sprintf("%d/%d", viewCount, *maxViews)
}

func formatTime(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}

	return parsed.Local().Format("2006-01-02 15:04")
}

func formatOptionalTime(value *string, fallback string) string {
	if value == nil {
		return fallback
	}

	return formatTime(*value)
}

// redactRef drops any key fragment before a reference is echoed.
func redactRef(value string) string {
	if before, _, found := strings.Cut(value, "#"); found {
		return before
	}

	return value
}
