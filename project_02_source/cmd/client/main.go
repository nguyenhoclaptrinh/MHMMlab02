package main

import (
	"lab02/pkg/client/api"
	"lab02/pkg/client/ui"
)

const ServerURL = "http://localhost:8080"

func main() {
	client := api.NewClient(ServerURL)
	app := ui.NewApp(client)
	app.Run()
}
