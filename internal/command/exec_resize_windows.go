//go:build windows

package command

import (
	"context"
	"os"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func watchTerminalResize(context.Context, *os.File, sdk.ExecSession) func() { return func() {} }
