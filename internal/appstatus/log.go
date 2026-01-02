package appstatus

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
)

type SlogContextHandler struct {
	baseHandler slog.Handler
}

func NewSlogContextHandler(h slog.Handler) slog.Handler {
	return SlogContextHandler{h}
}

func NewSlogLogger(w io.Writer) *slog.Logger {
	opt := slog.HandlerOptions{
		AddSource:   true,
		Level:       slog.LevelDebug,
		ReplaceAttr: SlogReplaceAttr,
	}
	jsonHandler := slog.NewJSONHandler(w, &opt)
	return slog.New(NewSlogContextHandler(jsonHandler))
}

func (c SlogContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if v := ctx.Value(RequestIdKey{}); v != nil {
		r.AddAttrs(slog.String("reqid", v.(string)))
	}
	return c.baseHandler.Handle(ctx, r)
}

func (c SlogContextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return c.baseHandler.Enabled(ctx, l)
}

func (c SlogContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return c.baseHandler.WithAttrs(attrs)
}

func (c SlogContextHandler) WithGroup(name string) slog.Handler {
	return c.baseHandler.WithGroup(name)
}

func SlogReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	err, ok := a.Value.Any().(error)
	if !ok || err == nil {
		return a
	}
	errWithStack := findErrorWithStack(err)

	if errWithStack == nil {
		return a
	}

	frames := runtime.CallersFrames(errWithStack.Stack)
	stacks := []map[string]any{}
	for {
		frame, more := frames.Next()
		stacks = append(stacks,
			map[string]any{
				"function": frame.Function,
				"file":     frame.File,
				"line":     frame.Line,
			},
		)
		if !more {
			break
		}
	}
	return slog.Attr{
		Key: "error",
		Value: slog.GroupValue(
			slog.String("message", fmt.Sprintf("%v", err)),
			slog.Any("stacktrace", stacks),
		),
	}
}
