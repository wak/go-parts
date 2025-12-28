package appstatus

import (
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"
)

func Test_Handler(t *testing.T) {
	// c := NewContext("req-0123")
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

func Test_Context(t *testing.T) {
	var buf bytes.Buffer
	h := NewSlogContextHandler(slog.NewJSONHandler(&buf, nil))

	logger := slog.New(h)
	ctx := NewContext("req-0123")
	logger.InfoContext(ctx, "contest log test")
	if !strings.Contains(buf.String(), "req-0123") {
		t.Errorf("Context data not found: %s", buf.String())
	}
}
