package testutil

import "testing"

func MustSuccess(t *testing.T, e error, args ...any) {
	t.Helper()
	if e != nil {
		switch len(args) {
		case 0:
			t.Fatalf("Must success, but failed: %v", e)
		case 1:
			t.Fatalf("%s: %v", args[0], e)
		default:
			t.Fatalf(args[0].(string), args[1:]...)
		}
	}
}

func MustOk(t *testing.T, ok bool, args ...any) {
	t.Helper()
	if !ok {
		switch len(args) {
		case 0:
			t.Fatal("Must ok, but failed.")
		default:
			t.Fatalf(args[0].(string), args[1:]...)
		}
	}
}

func MustError(t *testing.T, e error, args ...any) {
	t.Helper()
	if e == nil {
		switch len(args) {
		case 0:
			t.Fatal("Must error, but succeed.")
		default:
			t.Fatalf(args[0].(string), args[1:]...)
		}
	}
}

//lint:ignore U1000 Helper
func ExpectPanic(t *testing.T) {
	t.Helper()
	if r := recover(); r == nil {
		t.Fatalf("expected panic, but did not panic")
	}
}
