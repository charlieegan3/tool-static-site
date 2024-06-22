package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/viper"

	"github.com/charlieegan3/toolbelt/pkg/tool"

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

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cancel()
	}()

	// init the toolbelt, connecting the database, config and external runner
	tb := tool.NewBelt()
	tb.SetConfig(cfg)

	t := ssTool.StaticSite{}

	err = tb.AddTool(ctx, &t)
	if err != nil {
		cancel()

		log.Fatalf("failed to add tool: %v", err)
	}

	port := 3000
	address := "localhost"
	log.Printf("Starting server on http://%s:%d\n", address, port)
	tb.RunServer(ctx, address, strconv.Itoa(port))
}
