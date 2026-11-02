//go:build windows

package command

import (
	"context"
	sdk "github.com/QUOINER/sandboxes-go-sdk"
	"os"
)

func watchTerminalResize(context.Context, *os.File, sdk.ExecSession) func() { return func() {} }
