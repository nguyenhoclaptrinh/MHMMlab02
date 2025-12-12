package main

import (
	"os"
	"runtime"

	"lab02/pkg/client/api"
	"lab02/pkg/client/ui"

	"golang.org/x/sys/windows"
)

const ServerURL = "http://localhost:8080"

func main() {
	if runtime.GOOS == "windows" {
		enableWindowsVirtualTerminal()
	}

	client := api.NewClient(ServerURL)
	app := ui.NewApp(client)
	app.Run()
}

func enableWindowsVirtualTerminal() {
	stdout := windows.Handle(os.Stdout.Fd())
	var originalMode uint32
	if err := windows.GetConsoleMode(stdout, &originalMode); err != nil {
		// Fail silently or log if debugging, but here we just return as it's likely not a TTY (e.g. Mintty)
		return
	}
	windows.SetConsoleMode(stdout, originalMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
