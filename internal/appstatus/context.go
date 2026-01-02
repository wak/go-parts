package appstatus

import (
	"context"
)

type RequestIdKey struct{}

func NewContext(requestId string) context.Context {
	return context.WithValue(
		context.Background(),
		RequestIdKey{},
		requestId,
	)
}
