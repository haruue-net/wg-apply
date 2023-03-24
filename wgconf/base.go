package wgconf

import (
	"context"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type parserContextKey string

const ctxkParserOptions parserContextKey = "parser-options"

type ParserOptions struct {
	ProbeParser bool
	Path        string
	Interface   string
}

var ErrProbeParserMismatch = errors.New("probe parser mismatch")

func ExtractParserOptions(ctx context.Context) (po *ParserOptions) {
	po, _ = ctx.Value(ctxkParserOptions).(*ParserOptions)
	return
}

type Parser func(ctx context.Context) (conf *Config, err error)

var parserList = map[string]Parser{}

func RegisterParser(name string, parser Parser) {
	if _, ok := parserList[name]; ok {
		panic("parser already registered: " + name)
	}
	parserList[name] = parser
}

func Parse(ctx context.Context, parser string, ifce, path string) (conf *Config, err error) {
	opts := &ParserOptions{
		Interface:   ifce,
		Path:        path,
		ProbeParser: parser == "",
	}
	ctx = context.WithValue(ctx, ctxkParserOptions, opts)

	if parser != "" {
		if parser, ok := parserList[parser]; ok {
			conf, err = parser(ctx)
			return
		}
		err = fmt.Errorf("unknown parser: %s", parser)
		return
	}

	for _, parser := range parserList {
		conf, err = parser(ctx)
		if err != nil {
			if err == ErrProbeParserMismatch {
				err = nil
				continue
			}
			return
		}
		return
	}
	err = errors.New("cannot detect correct parser, please specify explicitly")
	return
}

type Config struct {
	Interface string
	WireGuard wgtypes.Config
	Network   NetworkConfig
}
