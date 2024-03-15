package check_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.szostok.io/codeowners-validator/internal/check"

	"go.szostok.io/codeowners-validator/pkg/codeowners"
)

var FixtureValidCODEOWNERS = `
		# These owners will be the default owners for everything
		*       @global-owner1 @global-owner2

		# js owner
		*.js    @js-owner

		*.go docs@example.com

		/build/logs/ @doctocat

		/script m.t@g.com
`

func LoadInput(in string) check.Input {
	r := strings.NewReader(in)

	return check.Input{
		CodeownersEntries: codeowners.ParseCodeowners(r),
	}
}

func assertIssue(t *testing.T, expIssue *check.Issue, gotIssues []check.Issue) {
	t.Helper()

	if expIssue != nil {
		require.Len(t, gotIssues, 1)
		assert.EqualValues(t, *expIssue, gotIssues[0])
	} else {
		assert.Empty(t, gotIssues)
	}
}

func Contains[K comparable](target K, list ...K) bool {
	for _, k := range list {
		if k == target {
			return true
		}
	}
	return false
}

// Context returns a context that is canceled when the test ends.
// If the test has a deadline, the returned context is canceled when the deadline is reached.
//
// Use instead of context.Background().
func Context(tb testing.TB) context.Context {
	ctx := context.Background()
	var cancel func()
	switch t := tb.(type) {
	case *testing.T:
		if d, ok := t.Deadline(); ok {
			ctx, cancel = context.WithDeadline(ctx, d)
		}
	}
	if cancel == nil {
		ctx, cancel = context.WithCancel(ctx)
	}
	tb.Cleanup(cancel)
	return ctx
}
