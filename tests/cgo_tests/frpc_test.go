package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testServerAddr = "127.0.0.1"
	testServerPort = 7000
	testToken     = "test_token"
)

func TestFrpcSession(t *testing.T) {
	// Skip if we're in a CI environment
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping test in CI environment")
	}

	// Create a new frpc session
	session, err := NewFrpcSession(testServerAddr, testServerPort, testToken, true)
	if !assert.NoError(t, err, "Failed to create frpc session") {
		return
	}
	defer session.Destroy()

	// Test adding a TCP proxy
	t.Run("AddTCPProxy", func(t *testing.T) {
		err := session.AddTcpProxy("test_tcp", "127.0.0.1", 8080, 8081)
		assert.NoError(t, err, "Failed to add TCP proxy")
	})

	// Test adding an STCP visitor
	t.Run("AddStcpVisitor", func(t *testing.T) {
		err := session.AddStcpVisitor("test_stcp_visitor", "test_server", "test_sk", 7001)
		assert.NoError(t, err, "Failed to add STCP visitor")
	})

	// Note: The actual connection test would require a running frps server
}

// TestMain handles setup and teardown for all tests
func TestMain(m *testing.M) {
	// Setup code here if needed

	// Run tests
	exitCode := m.Run()

	// Teardown code here if needed

	os.Exit(exitCode)
}

// Note: isPortInUse function is now located in test_common.go
