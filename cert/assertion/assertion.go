package assertion

import (
	"fmt"
	"time"
)

func AssertWithinRange(v, min, max int) (err error) {
	if v <= max && v >= min {
		return
	}
	return fmt.Errorf("assertion: %d was not >= %d and <= %d", v, min, max)
}

func AssertGreaterThan(v, min int) (err error) {
	if v > min {
		return
	}
	return fmt.Errorf("assertion: %d was not > %d", v, min)
}

func AssertExactly(v, e int) (err error) {
	if v == e {
		return
	}
	return fmt.Errorf("assertion: %d was not == %d", v, e)
}

func AssertTimeNotZero(t time.Time) (err error) {
	if !t.IsZero() {
		return
	}
	return fmt.Errorf("assertion: time was of zero value")
}

func AssertTimeNotNegative(t time.Time) (err error) {
	if (t.UnixMilli() - time.Time{}.UnixMilli()) >= 0 {
		return
	}
	return fmt.Errorf("assertion: time was negative")
}
