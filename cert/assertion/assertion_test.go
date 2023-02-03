package assertion

import (
	"testing"
	"time"

	r "github.com/stretchr/testify/require"
)

func TestAssertEqualSize(t *testing.T) {
	t.Parallel()

	r.NoError(t, AssertExactly(1, 1))
	r.NoError(t, AssertExactly(-1, -1))
	r.Error(t, AssertExactly(1, 2))
	r.Error(t, AssertExactly(2, 1))
	r.Error(t, AssertExactly(-1, 1))
}

func TestAssertTimeNotZero(t *testing.T) {
	t.Parallel()

	r.NoError(t, AssertTimeNotZero(time.Now()))
	r.Error(t, AssertTimeNotZero(time.Time{}))
}

func TestAssertWithinRange(t *testing.T) {
	t.Parallel()

	r.NoError(t, AssertWithinRange(1, 1, 1))
	r.NoError(t, AssertWithinRange(1, 1, 2))
	r.Error(t, AssertWithinRange(0, 1, 1))
	r.Error(t, AssertWithinRange(2, 1, 1))
	r.Error(t, AssertWithinRange(-1, 1, 1))
	r.Error(t, AssertWithinRange(-1, 0, 1))
}
