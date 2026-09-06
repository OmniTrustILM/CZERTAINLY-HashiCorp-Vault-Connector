package logger

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestFieldsReturnsNilWhenNoneSet(t *testing.T) {
	if fields := Fields(context.Background()); fields != nil {
		t.Fatalf("expected nil, got %v", fields)
	}
}

func TestWithFieldsRoundTrip(t *testing.T) {
	ctx := WithFields(context.Background(), zap.String("correlation_id", "abc"))

	fields := Fields(ctx)
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if fields[0].Key != "correlation_id" || fields[0].String != "abc" {
		t.Fatalf("unexpected field %+v", fields[0])
	}
}

func TestWithFieldsAppendsToExistingFields(t *testing.T) {
	ctx := WithFields(context.Background(), zap.String("first", "1"))
	ctx = WithFields(ctx, zap.String("second", "2"))

	fields := Fields(ctx)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}

	keys := map[string]bool{}
	for _, f := range fields {
		keys[f.Key] = true
	}
	if !keys["first"] || !keys["second"] {
		t.Fatalf("expected both fields to be present, got %v", fields)
	}
}

func TestWithFieldsDoesNotMutateParentContext(t *testing.T) {
	parent := WithFields(context.Background(), zap.String("first", "1"))
	WithFields(parent, zap.String("second", "2"))

	if len(Fields(parent)) != 1 {
		t.Fatalf("parent context was mutated: %v", Fields(parent))
	}
}

func TestWithCtxAndFromCtxRoundTrip(t *testing.T) {
	l := zap.NewNop()

	ctx := WithCtx(context.Background(), l)

	if got := FromCtx(ctx); got != l {
		t.Fatalf("expected the logger stored in the context, got %p", got)
	}
}

func TestWithCtxReturnsSameContextForSameLogger(t *testing.T) {
	l := zap.NewNop()
	ctx := WithCtx(context.Background(), l)

	if again := WithCtx(ctx, l); again != ctx {
		t.Fatal("expected the same context when storing an identical logger")
	}
}

func TestFromCtxReturnsUsableLoggerWhenNoneStored(t *testing.T) {
	if got := FromCtx(context.Background()); got == nil {
		t.Fatal("expected a usable logger, got nil")
	}
}

func TestGetReturnsTheSameLoggerOnRepeatedCalls(t *testing.T) {
	first := Get()
	if first == nil {
		t.Fatal("expected a logger, got nil")
	}

	if second := Get(); second != first {
		t.Fatal("expected Get to return the same instance on every call")
	}
}
