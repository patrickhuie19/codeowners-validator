package check_test

import (
	"context"
	"strings"
	"testing"

	"go.szostok.io/codeowners-validator/internal/check"

	"github.com/google/go-github/v41/github"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"go.szostok.io/codeowners-validator/internal/ptr"

	"github.com/stretchr/testify/assert"
)

type mockGithubClient struct {
	teams        mockTeams
	organization mockOrganization
	users        mockUsers
	repositories mockRepositories
}

func (m mockGithubClient) Teams() check.Teams {
	return m.teams
}

func (m mockGithubClient) Organizations() check.Organization {
	return m.organization
}

func (m mockGithubClient) Users() check.Users {
	return m.users
}

func (m mockGithubClient) Repositories() check.Repositories {
	return m.repositories
}

type mockTeams struct {
	repoIndex map[string]*github.Repository
	teams     []*github.Team
}

func (m mockTeams) IsTeamRepoBySlug(ctx context.Context, org, slug, owner, repo string) (*github.Repository, *github.Response, error) {
	gRepo, ok := m.repoIndex[repo]
	if !ok {
		panic("mockTeams.IsTeamRepoBySlug: repo " + repo + " not found")
	}
	return gRepo, &github.Response{NextPage: 0}, nil
}

func (m mockTeams) ListTeams(ctx context.Context, org string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
	return m.teams, &github.Response{NextPage: 0}, nil
}

type mockOrganization struct {
	users []*github.User
}

func (m mockOrganization) ListMembers(ctx context.Context, org string, opts *github.ListMembersOptions) ([]*github.User, *github.Response, error) {
	return m.users, &github.Response{NextPage: 0}, nil
}

type mockUsers struct {
	validUsers []string

	// explicit invalid
	invalidUsers []string
}

func (m mockUsers) Get(ctx context.Context, user string) (*github.User, *github.Response, error) {
	// undoes the @ prefix trim in business logic
	user = "@" + user

	if Contains(user, m.validUsers...) {
		return nil, nil, nil
	}
	if Contains(user, m.invalidUsers...) {
		return nil, nil, errors.New("mockUsers.Get: invalid user")
	}
	panic("mockUsers.Get: user " + user + " not found in valid or invalid list")
}

type mockRepositories struct {
}

func (m mockRepositories) Get(ctx context.Context, orgName, orgRepo string) (*github.Repository, *github.Response, error) {
	// Repository is always valid to run valid_owner checks
	return nil, nil, nil
}

func newMockGithubClient(users []string, invalidUsers []string) *mockGithubClient {
	return &mockGithubClient{
		teams:        *newMockTeams(teamNamesFromUsers(users)),
		organization: *newMockOrganization(users),
		repositories: *newMockRepositories(),
		users:        *newMockUsers(users, invalidUsers),
	}
}

func teamNamesFromUsers(users []string) []string {
	var teamNames []string
	for _, user := range users {
		if !strings.Contains(user, "/") {
			continue
		}
		parts := strings.SplitN(user, "/", 2)
		team := parts[1]
		teamNames = append(teamNames, team)
	}
	return teamNames
}

func newMockOrganization(users []string) *mockOrganization {
	var githubUsers []*github.User
	if users == nil {
		return &mockOrganization{}
	}
	for _, user := range users {
		userName := strings.TrimPrefix(user, "@")
		githubUsers = append(githubUsers, &github.User{Login: &userName})
	}
	return &mockOrganization{users: githubUsers}
}

func newMockTeams(teamNames []string) *mockTeams {
	githubTeams := make([]*github.Team, len(teamNames))

	for i := range teamNames {
		// Note: To create the slug, GitHub replaces special characters in the name string,
		// changes all words to lowercase, and replaces spaces with a - separator.
		//
		// For ease of testing, no names with special characters, uppercase, or spaces should be used
		// **Assumes** Name == Slug

		teamName := teamNames[i]
		githubTeam := github.Team{Name: &teamName, Slug: &teamName}

		githubTeams[i] = &githubTeam
	}

	return &mockTeams{
		// This is a hack for IsTeamRepoBySlug; the same repos will be returned for all slugs
		repoIndex: map[string]*github.Repository{
			"repo": {
				Permissions: map[string]bool{
					"maintain": true, // "admin", "maintain", "push" all valid
				},
			},
		},
		teams: githubTeams,
	}
}

func newMockRepositories() *mockRepositories {
	return &mockRepositories{}
}

func newMockUsers(validUsers []string, invalidUsers []string) *mockUsers {
	return &mockUsers{
		validUsers:   validUsers,
		invalidUsers: invalidUsers,
	}
}

func TestValidOwnerChecker(t *testing.T) {
	tests := map[string]struct {
		owner   string
		isValid bool
	}{
		"Invalid Email": {
			owner:   `asda.comm`,
			isValid: false,
		},
		"Valid Email": {
			owner:   `gmail@gmail.com`,
			isValid: true,
		},
		"Invalid Team": {
			owner:   `@org/`,
			isValid: false,
		},
		"Valid Team": {
			owner:   `@org/user`,
			isValid: true,
		},
		"Invalid User": {
			owner:   `user`,
			isValid: false,
		},
		"Valid User": {
			owner:   `@user`,
			isValid: true,
		},
	}
	for tn, tc := range tests {
		t.Run(tn, func(t *testing.T) {
			// when
			result := check.IsValidOwner(tc.owner)
			assert.Equal(t, tc.isValid, result)
		})
	}
}

func TestValidOwnerCheckerIgnoredOwner(t *testing.T) {
	t.Run("Should ignore owner", func(t *testing.T) {
		// given
		ownerCheck, err := check.NewValidOwner(check.ValidOwnerConfig{
			Repository:    "org/repo",
			IgnoredOwners: []string{"@owner1"},
		}, nil, true)
		require.NoError(t, err)

		givenCodeowners := `*	@owner1`

		// when
		out, err := ownerCheck.Check(context.Background(), LoadInput(givenCodeowners))

		// then
		require.NoError(t, err)
		assert.Empty(t, out.Issues)
	})

	t.Run("Should ignore user only and check the remaining owners", func(t *testing.T) {
		tests := map[string]struct {
			codeowners           string
			issue                *check.Issue
			allowUnownedPatterns bool
		}{
			"No owners": {
				codeowners: `*`,
				issue: &check.Issue{
					Severity: check.Error,
					LineNo:   ptr.Uint64Ptr(1),
					Message:  "Missing owner, at least one owner is required",
				},
			},
			"Bad owner definition": {
				codeowners: `*	badOwner`,
				issue: &check.Issue{
					Severity: check.Error,
					LineNo:   ptr.Uint64Ptr(1),
					Message:  `Not valid owner definition "badOwner"`,
				},
			},
			"No owners but allow empty": {
				codeowners:           `*`,
				issue:                nil,
				allowUnownedPatterns: true,
			},
		}
		for tn, tc := range tests {
			t.Run(tn, func(t *testing.T) {
				// given
				ownerCheck, err := check.NewValidOwner(check.ValidOwnerConfig{
					Repository:           "org/repo",
					AllowUnownedPatterns: tc.allowUnownedPatterns,
					IgnoredOwners:        []string{"@owner1"},
				}, nil, true)
				require.NoError(t, err)

				// when
				out, err := ownerCheck.Check(context.Background(), LoadInput(tc.codeowners))

				// then
				require.NoError(t, err)
				assertIssue(t, tc.issue, out.Issues)
			})
		}
	})
}

func TestValidOwnerCheckerOwnersMustBeTeams(t *testing.T) {
	tests := map[string]struct {
		codeowners           string
		issue                *check.Issue
		allowUnownedPatterns bool
	}{
		"Bad owner definition": {
			codeowners: `*	@owner1`,
			issue: &check.Issue{
				Severity: check.Error,
				LineNo:   ptr.Uint64Ptr(1),
				Message:  `Only team owners allowed and "@owner1" is not a team`,
			},
		},
		"No owners but allow empty": {
			codeowners:           `*`,
			issue:                nil,
			allowUnownedPatterns: true,
		},
	}
	for tn, tc := range tests {
		t.Run(tn, func(t *testing.T) {
			// given
			ownerCheck, err := check.NewValidOwner(check.ValidOwnerConfig{
				Repository:           "org/repo",
				AllowUnownedPatterns: tc.allowUnownedPatterns,
				OwnersMustBeTeams:    true,
			}, nil, true)
			require.NoError(t, err)

			// when
			out, err := ownerCheck.Check(context.Background(), LoadInput(tc.codeowners))

			// then
			require.NoError(t, err)
			assertIssue(t, tc.issue, out.Issues)
		})
	}
}

func TestValidOwnerCheckerOnlyOneOwner(t *testing.T) {
	tests := map[string]struct {
		codeowners           string
		issue                *check.Issue
		allowUnownedPatterns bool
		validUsers           []string
	}{
		"No owners fails": {
			codeowners: `*`,
			issue: &check.Issue{
				Severity: check.Error,
				LineNo:   ptr.Uint64Ptr(1),
				Message:  `Missing owner, at least one owner is required`,
			},
			validUsers: nil,
		},
		"One owner succeeds": {
			codeowners: `* @owner1`,
			issue:      nil,
			validUsers: []string{"@owner1"},
		},
		"Two user owners fails": {
			codeowners: `* @owner1 @owner2`,
			issue: &check.Issue{
				Severity: check.Error,
				LineNo:   ptr.Uint64Ptr(1),
				Message:  `Multiple Owners Detected`,
			},
			validUsers: []string{"@owner1", "@owner2"},
		},
		"Two team owners fails": {
			codeowners: `* @org/team1 @org/team2`,
			issue: &check.Issue{
				Severity: check.Error,
				LineNo:   ptr.Uint64Ptr(1),
				Message:  `Multiple Owners Detected`,
			},
			validUsers: []string{"@org/team1", "@org/team2"},
		},
		"One user and one team owner fails": {
			codeowners: `*	@owner1 @org/team1`,
			issue: &check.Issue{
				Severity: check.Error,
				LineNo:   ptr.Uint64Ptr(1),
				Message:  `Multiple Owners Detected`,
			},
			validUsers: []string{"@owner1", "@org/team1"},
		},
	}
	for tn, tc := range tests {
		t.Run(tn, func(t *testing.T) {
			ghClient := newMockGithubClient(tc.validUsers, nil)

			// given
			ownerCheck, err := check.NewValidOwner(check.ValidOwnerConfig{
				Repository: "org/repo",
			}, ghClient, false)
			require.NoError(t, err)

			// when
			out, err := ownerCheck.Check(context.Background(), LoadInput(tc.codeowners))

			// then
			require.NoError(t, err)
			assertIssue(t, tc.issue, out.Issues)
		})
	}
}
