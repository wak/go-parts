package appstatus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"
)

func Test_LogHandler(t *testing.T) {
	var buf bytes.Buffer
	h := NewSlogContextHandler(slog.NewJSONHandler(&buf, nil))

	results := func() []map[string]any {
		var ms []map[string]any
		for line := range bytes.SplitSeq(buf.Bytes(), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatal(err)
			}
			ms = append(ms, m)
		}
		return ms
	}
	// slogtest側で適当なデータが送られる
	err := slogtest.TestHandler(h, results)
	if err != nil {
		log.Fatal(err)
	}
}

func Test_ContextLog(t *testing.T) {
	var buf bytes.Buffer
	h := NewSlogContextHandler(slog.NewJSONHandler(&buf, nil))

	logger := slog.New(h)
	ctx := NewContext("req-0123")
	logger.InfoContext(ctx, "contest log test")
	if !strings.Contains(buf.String(), "req-0123") {
		t.Errorf("Context data not found: %s", buf.String())
	}
}

func Test_ErrorWithStackLog(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSlogLogger(&buf)

	e := errors.New("e1")
	e = fmt.Errorf("w %w %w", e, WrapStack(errors.New("e2")))
	logger.Info("stack log test", "error", e)
	if !strings.Contains(buf.String(), "stacktrace") {
		t.Errorf("stacktrace not found: %s", buf.String())
	}
}

func Test_ErrorWithoutStackLog(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSlogLogger(&buf)

	e := errors.New("e1")
	logger.Info("stack log test", "error", e)
	if strings.Contains(buf.String(), "stacktrace") {
		t.Errorf("stacktrace should not contain: %s", buf.String())
	}
}

func Test_findErrorWithStack(t *testing.T) {
	newError := func(e error) error {
		return WrapStack(e)
	}
	e1 := errors.New("e1")
	es1 := WrapStack(errors.New("es1"))
	es2 := newError(errors.New("es2"))
	joined1 := errors.Join(e1, es1)

	testDataSet := []struct {
		err        error
		returnsNil bool
		message    string
	}{
		// nil 対応
		{nil, true, "findErrorWithStack(nil) must return nil"},

		// Stack入りエラーなし 対応
		{e1, true, "findErrorWithStack(standard error) must return nil"},

		// 複数Stack入り 対応
		{
			fmt.Errorf("%w %w",
				es2,
				errors.Join(e1, es1),
			),
			false,
			"findErrorWithStack(multi stack) must return error",
		},

		// Join 対応
		{
			errors.Join(e1, es1),
			false,
			"findErrorWithStack(Joined) must return error",
		},

		// Wrap 対応
		{
			fmt.Errorf("wrapped %w", es1),
			false,
			"findErrorWithStack(Wrapped) must return error",
		},

		// 循環対応
		{
			errors.Join(joined1, joined1, joined1),
			false,
			"findErrorWithStack(Joined) must return error",
		},
	}

	for _, data := range testDataSet {
		r := findErrorWithStack(data.err)
		if (r == nil) != data.returnsNil {
			t.Errorf("%s: %v", data.message, r)
		}
	}
}
