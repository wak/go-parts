package appstatus

import (
	"fmt"
	"runtime"
	"strings"
)

type errorWithStack struct {
	Err   error
	Stack []uintptr
}

func stack(skip int) []uintptr {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(skip, pcs)
	return pcs[:n]
}

func NewErrorWithStack(err error) error {
	return &errorWithStack{
		Err:   err,
		Stack: stack(3),
	}
}

func (e *errorWithStack) Error() string {
	return e.Err.Error()
}

func (e *errorWithStack) Unwrap() error {
	return e.Err
}

func findErrorWithStack(err error) *errorWithStack {
	if err == nil {
		return nil
	}

	errors := []error{err}
	visited := map[error]struct{}{}
	errorWithStacks := []*errorWithStack{}

	for len(errors) > 0 {
		// POP
		e := errors[len(errors)-1]
		errors = errors[:len(errors)-1]

		// 循環対策
		if _, ok := visited[e]; ok {
			continue
		} else {
			visited[e] = struct{}{}
		}

		if m, ok := e.(*errorWithStack); ok {
			errorWithStacks = append(errorWithStacks, m)
		}

		// Join
		if m, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range m.Unwrap() {
				errors = append(errors, child)
			}
		}

		// Wrap
		if u, ok := e.(interface{ Unwrap() error }); ok {
			child := u.Unwrap()
			if child != nil {
				errors = append(errors, child)
			}
		}
	}

	if len(errorWithStacks) == 0 {
		return nil
	}

	var deepestError *errorWithStack = errorWithStacks[0]
	for _, e := range errorWithStacks {
		if len(deepestError.Stack) < len(e.Stack) {
			deepestError = e
		}
	}
	return deepestError
}

func formatStack(pcs []uintptr) string {
	frames := runtime.CallersFrames(pcs)
	var b strings.Builder
	fmt.Fprintf(&b, "============== STACK TRACE ==============\n")
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&b, "= %s\n=\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	fmt.Fprintf(&b, "=========================================")
	return b.String()
}

func DumpError(err error) string {
	if err == nil {
		return ""
	}

	var b strings.Builder

	// 基本的には、標準のフォーマットを使う。
	fmt.Fprintf(&b, "%v", err)

	errors := []error{err}
	visited := map[error]struct{}{}

	for len(errors) > 0 {
		// POP
		e := errors[len(errors)-1]
		errors = errors[:len(errors)-1]

		// 循環対策
		if _, ok := visited[e]; ok {
			continue
		} else {
			visited[e] = struct{}{}
		}

		// スタックトレースがあれば表示
		if m, ok := e.(*errorWithStack); ok {
			fmt.Fprintf(&b, "\n--\n(%T) %v\n%s", e, e, formatStack(m.Stack))
		}

		// Join
		if m, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range m.Unwrap() {
				errors = append(errors, child)
			}
		}

		// Wrap
		if u, ok := e.(interface{ Unwrap() error }); ok {
			child := u.Unwrap()
			if child != nil {
				errors = append(errors, child)
			}
		}
	}

	return b.String()
}
