package appstatus

import (
	"context"
	"log/slog"
)

type SlogContextHandler struct {
	h slog.Handler
}

type RequestIdKey struct{}

func NewContext(requestId string) context.Context {
	return context.WithValue(
		context.Background(),
		RequestIdKey{},
		requestId,
	)
}

func NewSlogContextHandler(h slog.Handler) slog.Handler {
	return SlogContextHandler{h}
}

func (c SlogContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if v := ctx.Value(RequestIdKey{}); v != nil {
		r.AddAttrs(slog.String("reqid", v.(string)))
	}
	return c.h.Handle(ctx, r)
}

func (c SlogContextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return c.h.Enabled(ctx, l)
}

func (c SlogContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return c.h.WithAttrs(attrs)
}

func (c SlogContextHandler) WithGroup(name string) slog.Handler {
	return c.h.WithGroup(name)
}
