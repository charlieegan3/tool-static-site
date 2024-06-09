package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/charlieegan3/toolbelt/pkg/tool"
	"github.com/spf13/viper"

	ssTool "github.com/charlieegan3/tool-static-site/pkg/tool"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Fatal error config file: %s \n", err)
	}

	cfg, ok := viper.Get("tools").(map[string]interface{})
	if !ok {
		log.Fatalf("failed to read tools config in map[string]interface{} format")
		os.Exit(1)
	}

	// configure global cancel context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-c:
			cancel()
		}
	}()

	// init the toolbelt, connecting the database, config and external runner
	tb := tool.NewBelt()
	tb.SetConfig(cfg)

	t := ssTool.StaticSite{}
	err = tb.AddTool(ctx, &t)
	if err != nil {
		log.Fatalf("failed to add tool: %v", err)
	}

	port := 3000
	address := "localhost"
	fmt.Printf("Starting server on http://%s:%d\n", address, port)
	tb.RunServer(ctx, address, fmt.Sprintf("%d", port))
}
