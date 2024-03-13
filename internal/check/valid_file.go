package check

import (
	"context"
	"strings"

	"go.szostok.io/codeowners-validator/internal/ctxutil"
	"go.szostok.io/codeowners-validator/pkg/codeowners"
)

// Satisfies the Checker interface
type ValidFile struct {
	ignFiles map[string]struct{}
}

func NewValidFile(ignoredFiles []string) *ValidFile {
	ignFiles := make(map[string]struct{})
	for _, file := range ignoredFiles {
		ignFiles[file] = struct{}{}
	}
	return &ValidFile{
		ignFiles: ignFiles,
	}
}

// Check if defined patterns in a codeowner entry are valid.
//
// Checks:
// - if the pattern is a discrete file (i.e. ends in a .go, .md, etc.)
// - if the pattern is deeply nested (more than 4 levels deep)
func (v *ValidFile) Check(ctx context.Context, in Input) (Output, error) {
	var bldr OutputBuilder

	for _, entry := range in.CodeownersEntries {
		permErr := v.checkPerEntry(ctx, entry, &bldr); if permErr != nil {
			return bldr.Output(), permErr
		}
	}
	return bldr.Output(), nil
}

func (v *ValidFile) checkPerEntry(ctx context.Context, entry codeowners.Entry, bldr *OutputBuilder) (permError error) {
	if ctxutil.ShouldExit(ctx) {
		return ctx.Err()
	}

	if _, ok := v.ignFiles[entry.Pattern]; ok {
		return nil
	}

	if isFile(entry.Pattern) {
		bldr.ReportIssue("Discrete file", WithSeverity(Warning), WithEntry(entry))
	}

	if isDeeplyNested(entry.Pattern) {
		bldr.ReportIssue("Deeply nested pattern", WithSeverity(Warning), WithEntry(entry))
	}

	return nil
}

// Checks if the pattern is a discrete file (i.e. ends in a .go, .md, etc.)
func isFile(pattern string) bool {
	if (strings.Contains(pattern, ".")) {
		split := strings.Split(pattern, ".")
		if len(split) > 1 {
			return true
		}
	}

	return false
}

// Checks if the pattern is deeply nested (more than 4 levels deep)
func isDeeplyNested(pattern string) bool {
	if (strings.Contains(pattern, "/")) {
		split := strings.SplitN(pattern, "/", 4)
		if len(split) > 3 {
			return true
		}
	}
	
	return false
}

func (v *ValidFile) Name() string {
	return "Valid File Checker"
}