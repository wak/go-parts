package appstatus

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func Test_StackTrace(t *testing.T) {
	e := WrapStack(errors.New("error for Test"))
	dumped := DumpError(e)

	if !strings.Contains(dumped, "error for Test") {
		t.Errorf("Error string not found: %s", e)
	}
	if !strings.Contains(dumped, "STACK TRACE") {
		t.Errorf("Stack trace not found: %s", e)
	}
}

func Test_DumpError_Recursive(t *testing.T) {
	e1 := WrapStack(errors.New("error for Test"))
	e2 := errors.New("test")
	e3 := errors.Join(e1, e2)
	e3 = fmt.Errorf("%w %w", e1, e3)

	dumped := DumpError(e3)

	if !strings.Contains(dumped, "STACK TRACE") {
		t.Errorf("Stack trace not found: %s", e3)
	}
}

func Test_DumpError_Nil(t *testing.T) {
	dumped := DumpError(nil)

	if dumped != "" {
		t.Errorf("Dumped message not empty: %s", dumped)
	}
}

func Test_WrapStack(t *testing.T) {
	e := errors.New("test")
	err := WrapStack(e)

	if errors.Is(err, e) != true {
		t.Error("errors.Is() must return true.")
	}
}

func Test_NewError(t *testing.T) {
	e := NewError("stack error")

	if e == nil {
		t.Error("NewError() must return error.")
	}
}
