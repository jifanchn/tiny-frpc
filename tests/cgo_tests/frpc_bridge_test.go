package main

import (
	"testing"
)

func TestFrpcInit(t *testing.T) {
	session, err := NewFrpcSession("127.0.0.1", 7000, "test_token", true)
	if err != nil {
		t.Fatalf("Failed to create frpc session: %v", err)
	}
	defer session.Destroy()

	// Test adding a TCP proxy
	err = session.AddTcpProxy("test_tcp", "127.0.0.1", 8080, 8081)
	if err != nil {
		t.Errorf("Failed to add TCP proxy: %v", err)
	}

	// Test adding an STCP visitor
	err = session.AddStcpVisitor("test_stcp", "server_name", "secret_key", 9000)
	if err != nil {
		t.Errorf("Failed to add STCP visitor: %v", err)
	}

	// Note: We're not calling session.Start() here as it's a blocking call
}

// TestFrpcIntegration tests the full integration with the C library
func TestFrpcIntegration(t *testing.T) {
	// This test requires the C library to be properly built and available
	// It will be skipped in short mode to avoid blocking during normal test runs
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	session, err := NewFrpcSession("127.0.0.1", 7000, "test_token", true)
	if err != nil {
		t.Fatalf("Failed to create frpc session: %v", err)
	}
	defer session.Destroy()

	// Add test configurations
	err = session.AddTcpProxy("test_tcp", "127.0.0.1", 8080, 8081)
	if err != nil {
		t.Fatalf("Failed to add TCP proxy: %v", err)
	}

	err = session.AddStcpVisitor("test_stcp", "server_name", "secret_key", 9000)
	if err != nil {
		t.Fatalf("Failed to add STCP visitor: %v", err)
	}

	// In a real test, you would start the session in a goroutine
	// and then test the actual functionality
	// go func() {
	//     if err := session.Start(); err != nil {
	//         t.Errorf("Failed to start frpc: %v", err)
	//     }
	// }()
}
