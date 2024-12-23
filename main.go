package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/charlieegan3/toolbelt/pkg/tool"

	ssTool "github.com/charlieegan3/tool-static-site/pkg/tool"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("no config file provided")

		os.Exit(1)
	}

	configFilePath := os.Args[1]

	log.Printf("loading config from %s\n", configFilePath)

	configFile, err := os.Open(configFilePath)
	if err != nil {
		log.Fatalf("failed to open config file: %v", err)
	}
	defer configFile.Close()

	var cfg map[string]any
	err = yaml.NewDecoder(configFile).Decode(&cfg)
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)

		os.Exit(1)
	}

	// configure global cancel context
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cancel()
	}()

	// init the toolbelt, connecting the database, config and external runner
	tb := tool.NewBelt()
	tb.SetConfig(map[string]any{"static-site": cfg})

	t := ssTool.StaticSite{}

	err = tb.AddTool(ctx, &t)
	if err != nil {
		cancel()

		log.Fatalf("failed to add tool: %v", err)
	}

	address := "localhost"

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("Starting server on http://%s:%s\n", address, port)

	tb.RunServer(ctx, address, port)
}
