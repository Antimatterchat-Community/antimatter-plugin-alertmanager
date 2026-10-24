// Copyright (c) 2019-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// main handles deployment of the plugin to a development server using the Client4 API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

const commandTimeout = 120 * time.Second

const helpText = `
Usage:
    pluginctl deploy <plugin id> <bundle path>
    pluginctl disable <plugin id>
    pluginctl enable <plugin id>
    pluginctl reset <plugin id>
`

func main() {
	err := pluginctl()
	if err != nil {
		fmt.Printf("Failed: %s\n", err.Error())
		fmt.Print(helpText)
		os.Exit(1)
	}
}

func pluginctl() error {
	if len(os.Args) < 3 {
		return errors.New("invalid number of arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	client, err := getClient(ctx)
	if err != nil {
		return err
	}

	switch os.Args[1] {
	case "deploy":
		if len(os.Args) < 4 {
			return errors.New("invalid number of arguments")
		}
		return deploy(ctx, client, os.Args[2], os.Args[3])
	case "disable":
		return disablePlugin(ctx, client, os.Args[2])
	case "enable":
		return enablePlugin(ctx, client, os.Args[2])
	case "reset":
		return resetPlugin(ctx, client, os.Args[2])
	case "logs":
		return logs(ctx, client, os.Args[2])
	case "logs-watch":
		return watchLogs(context.WithoutCancel(ctx), client, os.Args[2]) // Keep watching forever
	default:
		return errors.New("invalid second argument")
	}
}

// getEnv returns the value of the AM_-prefixed environment variable name, falling back to the
// legacy MM_-prefixed name when the AM_ one is unset or empty.
func getEnv(name string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	if legacy, ok := strings.CutPrefix(name, "AM_"); ok {
		return os.Getenv("MM_" + legacy)
	}
	return ""
}

func getClient(ctx context.Context) (*model.Client4, error) {
	socketPath := getEnv("AM_LOCALSOCKETPATH")
	if socketPath == "" {
		socketPath = model.LocalModeSocketPath
	}

	client, connected := getUnixClient(socketPath)
	if connected {
		log.Printf("Connecting using local mode over %s", socketPath)
		return client, nil
	}

	if getEnv("AM_LOCALSOCKETPATH") != "" {
		log.Printf("No socket found at %s for local mode deployment. Attempting to authenticate with credentials.", socketPath)
	}

	siteURL := os.Getenv("MM_SERVICESETTINGS_SITEURL")
	adminToken := getEnv("AM_ADMIN_TOKEN")
	adminUsername := getEnv("AM_ADMIN_USERNAME")
	adminPassword := getEnv("AM_ADMIN_PASSWORD")

	if siteURL == "" {
		return nil, errors.New("MM_SERVICESETTINGS_SITEURL is not set")
	}

	client = model.NewAPIv4Client(siteURL)

	if adminToken != "" {
		log.Printf("Authenticating using token against %s.", siteURL) //nolint:gosec // the developer's own server address
		client.SetToken(adminToken)
		return client, nil
	}

	if adminUsername != "" && adminPassword != "" {
		client := model.NewAPIv4Client(siteURL)
		log.Printf("Authenticating as %s against %s.", adminUsername, siteURL) //nolint:gosec // the developer's own settings
		_, _, err := client.Login(ctx, adminUsername, adminPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to login as %s: %w", adminUsername, err)
		}

		return client, nil
	}

	return nil, errors.New("one of AM_ADMIN_TOKEN or AM_ADMIN_USERNAME/AM_ADMIN_PASSWORD (or their MM_ equivalents) must be defined")
}

func getUnixClient(socketPath string) (*model.Client4, bool) {
	_, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, false
	}

	return model.NewAPIv4SocketClient(socketPath), true
}

// deploy attempts to upload and enable a plugin via the Client4 API.
// It will fail if plugin uploads are disabled.
func deploy(ctx context.Context, client *model.Client4, pluginID, bundlePath string) error {
	pluginBundle, err := os.Open(bundlePath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", bundlePath, err)
	}
	defer func() { _ = pluginBundle.Close() }()

	log.Print("Uploading plugin via API.")
	_, _, err = client.UploadPluginForced(ctx, pluginBundle)
	if err != nil {
		return fmt.Errorf("failed to upload plugin bundle: %s", err.Error())
	}

	log.Print("Enabling plugin.")
	_, err = client.EnablePlugin(ctx, pluginID)
	if err != nil {
		return fmt.Errorf("failed to enable plugin: %s", err.Error())
	}

	return nil
}

// disablePlugin attempts to disable the plugin via the Client4 API.
func disablePlugin(ctx context.Context, client *model.Client4, pluginID string) error {
	log.Print("Disabling plugin.")
	_, err := client.DisablePlugin(ctx, pluginID)
	if err != nil {
		return fmt.Errorf("failed to disable plugin: %w", err)
	}

	return nil
}

// enablePlugin attempts to enable the plugin via the Client4 API.
func enablePlugin(ctx context.Context, client *model.Client4, pluginID string) error {
	log.Print("Enabling plugin.")
	_, err := client.EnablePlugin(ctx, pluginID)
	if err != nil {
		return fmt.Errorf("failed to enable plugin: %w", err)
	}

	return nil
}

// resetPlugin attempts to reset the plugin via the Client4 API.
func resetPlugin(ctx context.Context, client *model.Client4, pluginID string) error {
	err := disablePlugin(ctx, client, pluginID)
	if err != nil {
		return err
	}

	err = enablePlugin(ctx, client, pluginID)
	if err != nil {
		return err
	}

	return nil
}
