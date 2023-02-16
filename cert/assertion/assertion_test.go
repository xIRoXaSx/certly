package assertion

import (
	"math"
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

func TestAssertTimeNotNegative(t *testing.T) {
	t.Parallel()

	r.NoError(t, AssertTimeNotNegative(time.Now()))
	r.NoError(t, AssertTimeNotNegative(time.Time{}))
	r.Error(t, AssertTimeNotNegative(time.Time{}.Add(-math.MaxInt64)))
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

func TestAssertGreaterThan(t *testing.T) {
	t.Parallel()

	r.NoError(t, AssertGreaterThan(2, 1))
	r.Error(t, AssertGreaterThan(1, 1))
	r.Error(t, AssertGreaterThan(0, 1))
	r.Error(t, AssertGreaterThan(-1, 1))
	r.Error(t, AssertGreaterThan(-1, 0))
}
