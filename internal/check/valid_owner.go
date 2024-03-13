package check

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"go.szostok.io/codeowners-validator/internal/ctxutil"
	"go.szostok.io/codeowners-validator/pkg/codeowners"

	"github.com/google/go-github/v41/github"
	"github.com/pkg/errors"
)

const scopeHeader = "X-OAuth-Scopes"

var reqScopes = map[github.Scope]struct{}{
	github.ScopeReadOrg: {},
}

type WrappedGithubClient interface {
	Teams() Teams
	Organizations() Organization
	Users() Users
	Repositories() Repositories
}

func NewWrappedGithubClient(inner *github.Client) WrappedGithubClient {
	return &WrappedGithubClientImpl{inner: inner}
}

type WrappedGithubClientImpl struct {
	inner *github.Client
}

func (g *WrappedGithubClientImpl) Teams() Teams {
	return g.inner.Teams
}

func (g *WrappedGithubClientImpl) Organizations() Organization {
	return g.inner.Organizations
}

func (g *WrappedGithubClientImpl) Users() Users {
	return g.inner.Users
}

func (g *WrappedGithubClientImpl) Repositories() Repositories {
	return g.inner.Repositories
}

type GithubClientImpl struct {
	Organization Organization
	Teams        Teams
	Users		 Users
	Repositories Repositories
}

type Organization interface {
	ListMembers(ctx context.Context, org string, opts *github.ListMembersOptions) ([]*github.User, *github.Response, error)
}

type Teams interface {
	ListTeams(ctx context.Context, org string, opts *github.ListOptions) ([]*github.Team, *github.Response, error)
	IsTeamRepoBySlug(ctx context.Context, org, slug, owner, repo string) (*github.Repository, *github.Response, error)
}

type Users interface {
	Get(ctx context.Context, user string) (*github.User, *github.Response, error)
}

type Repositories interface {
	Get(ctx context.Context, orgName, orgRepo string) (*github.Repository, *github.Response, error)
}

type ValidOwnerConfig struct {
	// Repository represents the GitHub repository against which
	// the external checks like teams and members validation should be executed.
	// It is in form 'owner/repository'.
	Repository string
	// IgnoredOwners contains a list of owners that should not be validated.
	// Defaults to @ghost.
	// More info about the @ghost user: https://docs.github.com/en/free-pro-team@latest/github/setting-up-and-managing-your-github-user-account/deleting-your-user-account
	// Tip on how @ghost can be used: https://github.community/t5/How-to-use-Git-and-GitHub/CODEOWNERS-file-with-a-NOT-file-type-condition/m-p/31013/highlight/true#M8523
	IgnoredOwners []string `envconfig:"default=@ghost"`
	// AllowUnownedPatterns specifies whether CODEOWNERS may have unowned files. For example:
	//
	//  /infra/oncall-rotator/                    @sre-team
	//  /infra/oncall-rotator/oncall-config.yml
	//
	//  The `/infra/oncall-rotator/oncall-config.yml` this file is not owned by anyone.
	AllowUnownedPatterns bool `envconfig:"default=true"`
	// OwnersMustBeTeams specifies whether owners must be teams in the same org as the repository
	OwnersMustBeTeams bool `envconfig:"default=false"`
}

// ValidOwner validates each owner
type ValidOwner struct {
	ghClient             WrappedGithubClient
	checkScopes          bool
	orgMembers           *map[string]struct{}
	orgName              string
	orgTeams             []*github.Team
	orgRepoName          string
	ignOwners            map[string]struct{}
	allowUnownedPatterns bool
	ownersMustBeTeams    bool
}

// NewValidOwner returns new instance of the ValidOwner
func NewValidOwner(cfg ValidOwnerConfig, ghClient WrappedGithubClient, checkScopes bool) (*ValidOwner, error) {
	split := strings.Split(cfg.Repository, "/")
	if len(split) != 2 {
		return nil, errors.Errorf("Wrong repository name. Expected pattern 'owner/repository', got '%s'", cfg.Repository)
	}

	ignOwners := map[string]struct{}{}
	for _, n := range cfg.IgnoredOwners {
		ignOwners[n] = struct{}{}
	}

	return &ValidOwner{
		ghClient:             ghClient,
		checkScopes:          checkScopes,
		orgName:              split[0],
		orgRepoName:          split[1],
		ignOwners:            ignOwners,
		allowUnownedPatterns: cfg.AllowUnownedPatterns,
		ownersMustBeTeams:    cfg.OwnersMustBeTeams,
	}, nil
}

// Check if defined owners are the valid ones.
// Allowed owner syntax:
// @username
// @org/team-name
// user@example.com
// source: https://help.github.com/articles/about-code-owners/#codeowners-syntax
//
// Checks:
// - if owner is one of: GitHub user, org team, email address
// - if GitHub user then check if have GitHub account
// - if GitHub user then check if he/she is in organization
// - if org team then check if exists in organization
// - if an entry has multiple owners
func (v *ValidOwner) Check(ctx context.Context, in Input) (Output, error) {
	var bldr OutputBuilder

	for _, entry := range in.CodeownersEntries {
		switch len(entry.Owners) {
		case 0:
			if !v.allowUnownedPatterns {
				bldr.ReportIssue("Missing owner, at least one owner is required", WithEntry(entry), WithSeverity(Error))
				continue
			}
		case 1:
			if err := v.checkPerEntry(ctx, entry, &bldr); err != nil {
				// permanent error
				return bldr.Output(), err
			}
			continue
		default:
			bldr.ReportIssue("Multiple Owners Detected", WithEntry(entry), WithSeverity(Error))

			if err := v.checkPerEntry(ctx, entry, &bldr); err != nil {
				// permanent error
				return bldr.Output(), err
			}
			continue
		}
	}

	return bldr.Output(), nil
}

func (v *ValidOwner) checkPerEntry(ctx context.Context, entry codeowners.Entry, bldr *OutputBuilder) (permError error) {
	checkedOwners := map[string]struct{}{}

	for _, ownerName := range entry.Owners {
		if ctxutil.ShouldExit(ctx) {
			return ctx.Err()
		}

		if v.isIgnoredOwner(ownerName) {
			continue
		}

		if _, alreadyChecked := checkedOwners[ownerName]; alreadyChecked {
			continue
		}

		validFn := v.selectValidateFn(ownerName)
		if err := validFn(ctx, ownerName); err != nil {
			bldr.ReportIssue(err.msg, WithEntry(entry))
			if err.permanent { // Doesn't make sense to process further
				return errors.New(err.msg)
			}
		}
		checkedOwners[ownerName] = struct{}{}
	}
	return nil
}

func isEmailAddress(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}

func isGitHubTeam(s string) bool {
	hasPrefix := strings.HasPrefix(s, "@")
	containsSlash := strings.Contains(s, "/")
	split := strings.SplitN(s, "/", 3) // 3 is enough to confirm that is invalid + will not overflow the buffer
	return hasPrefix && containsSlash && len(split) == 2 && len(split[1]) > 0
}

func isGitHubUser(s string) bool {
	return !strings.Contains(s, "/") && strings.HasPrefix(s, "@")
}

func (v *ValidOwner) isIgnoredOwner(name string) bool {
	_, found := v.ignOwners[name]
	return found
}

func (v *ValidOwner) selectValidateFn(name string) func(context.Context, string) *validateError {
	switch {
	case v.ownersMustBeTeams:
		return func(ctx context.Context, s string) *validateError {
			if !isGitHubTeam(name) {
				return newValidateWarning("Only team owners allowed and %q is not a team", name)
			}
			return v.validateTeam(ctx, s)
		}
	case isGitHubTeam(name):
		return v.validateTeam
	case isGitHubUser(name):
		return v.validateGitHubUser
	case isEmailAddress(name):
		// TODO(mszostok): try to check if e-mail really exists
		return func(context.Context, string) *validateError { return nil }
	default:
		return func(_ context.Context, name string) *validateError {
			return newValidateRuntimeError("Not valid owner definition %q", name)
		}
	}
}

func (v *ValidOwner) initOrgListTeams(ctx context.Context) *validateError {
	var teams []*github.Team
	req := &github.ListOptions{
		PerPage: 100,
	}
	for {
		result, resp, err := v.ghClient.Teams().ListTeams(ctx, v.orgName, req)
		if err != nil { // TODO(mszostok): implement retry?
			switch err := err.(type) {
			case *github.ErrorResponse:
				if err.Response.StatusCode == http.StatusUnauthorized {
					return newValidateRuntimeError("Teams for organization %q could not be queried. Requires GitHub authorization.", v.orgName)
				}
				return newValidateRuntimeError("HTTP error occurred while calling GitHub: %v", err)
			case *github.RateLimitError:
				return newValidateRuntimeError("GitHub rate limit reached: %v", err.Message)
			default:
				return newValidateRuntimeError("Unknown error occurred while calling GitHub: %v", err)
			}
		}
		teams = append(teams, result...)
		if resp.NextPage == 0 {
			break
		}
		req.Page = resp.NextPage
	}

	v.orgTeams = teams

	return nil
}

func (v *ValidOwner) validateTeam(ctx context.Context, name string) *validateError {
	if v.orgTeams == nil {
		if err := v.initOrgListTeams(ctx); err != nil {
			return err.AsPermanent()
		}
	}

	// called after validation it's safe to work on `parts` slice
	parts := strings.SplitN(name, "/", 2)
	org := parts[0]
	org = strings.TrimPrefix(org, "@")
	team := parts[1]

	// GitHub normalizes name before comparison
	if !strings.EqualFold(org, v.orgName) {
		return newValidateWarning("Team %q does not belong to %q organization.", name, v.orgName)
	}

	teamExists := func() bool {
		for _, v := range v.orgTeams {
			// GitHub normalizes name before comparison
			if strings.EqualFold(v.GetSlug(), team) {
				return true
			}
		}
		return false
	}

	if !teamExists() {
		return newValidateWarning("Team %q does not exist in organization %q.", name, org)
	}

	// repo contains the permissions for the team slug given
	// TODO(mszostok): Switch to GraphQL API, see:
	//   https://github.com/mszostok/codeowners-validator/pull/62#discussion_r561273525
	repo, _, err := v.ghClient.Teams().IsTeamRepoBySlug(ctx, v.orgName, team, org, v.orgRepoName)
	if err != nil { // TODO(mszostok): implement retry?
		switch err := err.(type) {
		case *github.ErrorResponse:
			switch err.Response.StatusCode {
			case http.StatusUnauthorized:
				return newValidateRuntimeError(
					"Team permissions information for %q/%q could not be queried. Requires GitHub authorization.",
					org, v.orgRepoName)
			case http.StatusNotFound:
				return newValidateWarning(
					"Team %q does not have permissions associated with the repository %q.",
					team, v.orgRepoName)
			default:
				return newValidateRuntimeError("HTTP error occurred while calling GitHub: %v", err)
			}
		case *github.RateLimitError:
			return newValidateRuntimeError("GitHub rate limit reached: %v", err.Message)
		default:
			return newValidateRuntimeError("Unknown error occurred while calling GitHub: %v", err)
		}
	}

	teamHasWritePermission := func() bool {
		for k, v := range repo.GetPermissions() {
			if !v {
				continue
			}

			switch k {
			case
				"admin",
				"maintain",
				"push":
				return true
			case
				"pull",
				"triage":
			}
		}

		return false
	}

	if !teamHasWritePermission() {
		return newValidateWarning(
			"Team %q cannot review PRs on %q as neither it nor any parent team has write permissions.",
			team, v.orgRepoName)
	}

	return nil
}

func (v *ValidOwner) validateGitHubUser(ctx context.Context, name string) *validateError {
	if v.orgMembers == nil { // TODO(mszostok): lazy init, make it more robust.
		if err := v.initOrgListMembers(ctx); err != nil {
			return newValidateRuntimeError("Cannot initialize organization member list: %v", err).AsPermanent()
		}
	}

	userName := strings.TrimPrefix(name, "@")
	_, _, err := v.ghClient.Users().Get(ctx, userName)
	if err != nil { // TODO(mszostok): implement retry?
		switch err := err.(type) {
		case *github.ErrorResponse:
			if err.Response.StatusCode == http.StatusNotFound {
				return newValidateRuntimeError("User %q does not have github account", name)
			}
			return newValidateRuntimeError("HTTP error occurred while calling GitHub: %v", err).AsPermanent()
		case *github.RateLimitError:
			return newValidateRuntimeError("GitHub rate limit reached: %v", err.Message).AsPermanent()
		default:
			return newValidateRuntimeError("Unknown error occurred while calling GitHub: %v", err).AsPermanent()
		}
	}

	_, isMember := (*v.orgMembers)[userName]
	if !isMember {
		return newValidateWarning("User %q is not a member of the organization", name)
	}

	return nil
}

// There is a method to check if user is a org member
//
//	client.Organizations.IsMember(context.Background(), "org-name", "user-name")
//
// But latency is too huge for checking each single user independent
// better and faster is to ask for all members and cache them.
func (v *ValidOwner) initOrgListMembers(ctx context.Context) error {
	opt := &github.ListMembersOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	var allMembers []*github.User
	for {
		users, resp, err := v.ghClient.Organizations().ListMembers(ctx, v.orgName, opt)
		if err != nil {
			return err
		}
		allMembers = append(allMembers, users...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	v.orgMembers = &map[string]struct{}{}
	for _, u := range allMembers {
		(*v.orgMembers)[u.GetLogin()] = struct{}{}
	}

	return nil
}

// Name returns human-readable name of the validator
func (ValidOwner) Name() string {
	return "Valid Owner Checker"
}

// CheckSatisfied checks if this check has all requirements satisfied to be successfully executed.
func (v *ValidOwner) CheckSatisfied(ctx context.Context) error {
	// TODO(patrickhuie19) create wrapper to simplify redundant
	// error handling code across all github API calls
	_, resp, err := v.ghClient.Repositories().Get(ctx, v.orgName, v.orgRepoName)
	if err != nil {
		switch err := err.(type) {
		case *github.ErrorResponse:
			if err.Response.StatusCode == http.StatusNotFound {
				return fmt.Errorf("repository %s/%s not found, or it's private and token doesn't have enough permission", v.orgName, v.orgRepoName)
			}
			return fmt.Errorf("HTTP error occurred while calling GitHub: %v", err)
		case *github.RateLimitError:
			return fmt.Errorf("GitHub rate limit reached: %v", err.Message)
		default:
			return fmt.Errorf("unknown error occurred while calling GitHub: %v", err)
		}
	}

	if !v.checkScopes {
		// If the GitHub client uses a GitHub App, the headers won't have scope information.
		// TODO: Call the https://api.github.com/app/installations and check if the `permission` field has `"members": "read"
		return nil
	}

	return v.checkRequiredScopes(resp.Header)
}

func (*ValidOwner) checkRequiredScopes(header http.Header) error {
	gotScopes := strings.Split(header.Get(scopeHeader), ",")
	presentScope := map[github.Scope]struct{}{}
	for _, scope := range gotScopes {
		scope = strings.TrimSpace(scope)
		presentScope[github.Scope(scope)] = struct{}{}
	}

	var missing []string
	for reqScope := range reqScopes {
		if _, found := presentScope[reqScope]; found {
			continue
		}
		missing = append(missing, string(reqScope))
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing scopes: %q", strings.Join(missing, ", "))
	}

	return nil
}
