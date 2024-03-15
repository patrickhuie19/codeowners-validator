package check_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.szostok.io/codeowners-validator/internal/check"
	"go.szostok.io/codeowners-validator/internal/ptr"
	"go.szostok.io/codeowners-validator/pkg/codeowners"
)

func TestValidFile(t *testing.T) {
	tests := map[string]struct {
		ignoredPatterns []string
		entries         []codeowners.Entry
		issue           *check.Issue
	}{
		"simple valid entry": {
			ignoredPatterns: []string{},
			entries: []codeowners.Entry{
				{LineNo: uint64(1), Pattern: "*", Owners: []string{"@org/team"}},
				{LineNo: uint64(1), Pattern: "level1/level2/level3", Owners: []string{"@org/team"}},
			},
		},
		"invalid entry: deeply nested": {
			ignoredPatterns: []string{},
			entries: []codeowners.Entry{
				{LineNo: uint64(1), Pattern: "level1/level2/level3/level4", Owners: []string{"@org/team"}},
			},
			issue: &check.Issue{Severity: check.Warning, LineNo: ptr.Uint64Ptr(1), Message: "Deeply nested pattern"},
		},
		"invalid entry: discrete file": {
			ignoredPatterns: []string{},
			entries: []codeowners.Entry{
				{LineNo: uint64(1), Pattern: "file.go", Owners: []string{"@org/team"}},
			},
			issue: &check.Issue{Severity: check.Warning, LineNo: ptr.Uint64Ptr(1), Message: "Discrete file"},
		},
		"ignored and invalid entries are ignored": {
			ignoredPatterns: []string{"file.go", "level1/level2/level3/level4"},
			entries: []codeowners.Entry{
				{LineNo: uint64(1), Pattern: "file.go", Owners: []string{"@org/team"}},
				{LineNo: uint64(1), Pattern: "level1/level2/level3/level4", Owners: []string{"@org/team"}},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// given
			vf := check.NewValidPattern(tt.ignoredPatterns)

			// when
			out, err := vf.Check(Context(t), check.Input{
				RepoDir:           "org/repo",
				CodeownersEntries: tt.entries,
			})

			// then
			assert.NoError(t, err)
			assertIssue(t, tt.issue, out.Issues)
		})
	}

}
