package logging

import (
	"fmt"
	"io"
	"log/slog"
)

type Options struct {
	Level  string
	Format string
}

func New(o Options, w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(o.Level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", o.Level, err)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch o.Format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("log format %q: want json or text", o.Format)
}
