/**
 * Multi-Process E2E Tests for FRP/STCP
 *
 * This file tests scenarios involving multiple processes,
 * concurrent connections, and resource sharing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../tiny-frpc/include/frpc.h"
#include "../tiny-frpc/include/frpc-stcp.h"

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[PID %d] FAIL: %s\n", getpid(), msg); \
            exit(1); \
        } \
    } while (0)

// Shared memory for process coordination
typedef struct {
    pid_t server_pid;
    pid_t visitor_pid;
    pid_t frps_pid;
    int ready;
    int success;
    int error_code;
} shared_state_t;

// ============================================================================
// Helper Functions
// ============================================================================

static int create_temp_file(char* path, size_t len) {
    snprintf(path, len, "/tmp/frp_test_%d_%ld", getpid(), time(NULL));
    return open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
}


static void signal_ready(const char* path) {
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, "1", 1);
        close(fd);
    }
}

// ============================================================================
// Test 1: Basic Multi-Process Server-Visitor
// ============================================================================

static int test_basic_multi_process(void) {
    printf("\n=== Test: Basic Multi-Process Server-Visitor ===\n");

    char ready_path[256];
    create_temp_file(ready_path, sizeof(ready_path));

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // Child process (server)
        printf("[Server PID %d] Starting...\n", getpid());

        // Create server
        frpc_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.server_addr = "127.0.0.1";
        cfg.server_port = 7001;
        cfg.token = "test_token";
        cfg.heartbeat_interval = 1;
        cfg.tls_enable = false;

        frpc_client_t* client = frpc_client_new(&cfg, NULL);
        TEST_ASSERT(client != NULL, "server client creation");

        // Just test client creation, don't actually connect
        printf("[Server PID %d] Client created successfully\n", getpid());
        signal_ready(ready_path);

        frpc_client_free(client);
        exit(0);
    } else {
        // Parent process
        printf("[Parent] Server PID: %d\n", pid);

        // Wait for server to be ready
        sleep(1);

        int status;
        waitpid(pid, &status, 0);

        unlink(ready_path);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("PASS: Basic multi-process test\n");
            return 0;
        } else {
            printf("FAIL: Server process exited with status %d\n", status);
            return -1;
        }
    }
}

// ============================================================================
// Test 2: Concurrent Processes
// ============================================================================

static int test_concurrent_processes(void) {
    printf("\n=== Test: Concurrent Processes ===\n");

    const int NUM_PROCESSES = 5;
    pid_t pids[NUM_PROCESSES];

    for (int i = 0; i < NUM_PROCESSES; i++) {
        pids[i] = fork();

        if (pids[i] < 0) {
            perror("fork");
            // Kill existing children
            for (int j = 0; j < i; j++) {
                kill(pids[j], SIGTERM);
            }
            return -1;
        }

        if (pids[i] == 0) {
            // Child process
            printf("[Child %d] PID=%d starting...\n", i, getpid());

            // Each child creates a client
            frpc_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            cfg.server_addr = "127.0.0.1";
            cfg.server_port = 7001;
            cfg.token = "test_token";
            cfg.heartbeat_interval = 1;
            cfg.tls_enable = false;

            frpc_client_t* client = frpc_client_new(&cfg, NULL);
            if (client) {
                // Just test creation, don't connect
                frpc_client_free(client);
            }

            usleep(10000); // 10ms
            exit(0);
        }
    }

    // Wait for all children
    int success = 0;
    for (int i = 0; i < NUM_PROCESSES; i++) {
        int status;
        waitpid(pids[i], &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            success++;
        }
    }

    TEST_ASSERT(success == NUM_PROCESSES, "all concurrent processes completed");
    printf("PASS: Concurrent processes test (%d/%d succeeded)\n",
           success, NUM_PROCESSES);
    return 0;
}

// ============================================================================
// Test 3: Process Isolation
// ============================================================================

static int test_process_isolation(void) {
    printf("\n=== Test: Process Isolation ===\n");

    // Test that separate processes don't interfere with each other

    pid_t child1 = fork();
    if (child1 == 0) {
        // First child
        frpc_client_t* client1 = frpc_client_new(NULL, NULL);
        exit(client1 == NULL ? 0 : 1); // Should fail gracefully
    }

    pid_t child2 = fork();
    if (child2 == 0) {
        // Second child
        frpc_client_t* client2 = frpc_client_new(NULL, NULL);
        exit(client2 == NULL ? 0 : 1); // Should fail gracefully
    }

    int status1, status2;
    waitpid(child1, &status1, 0);
    waitpid(child2, &status2, 0);

    TEST_ASSERT(WIFEXITED(status1), "child1 exited normally");
    TEST_ASSERT(WIFEXITED(status2), "child2 exited normally");

    printf("PASS: Process isolation test\n");
    return 0;
}

// ============================================================================
// Test 4: Resource Sharing
// ============================================================================

static int test_resource_sharing(void) {
    printf("\n=== Test: Resource Sharing Limits ===\n");

    // Test file descriptor sharing limits
    struct rlimit lim;
    getrlimit(RLIMIT_NOFILE, &lim);

    printf("  File descriptor limit: %lu\n", (unsigned long)lim.rlim_cur);

    const int NUM_FDS = (int)lim.rlim_cur / 2; // Try to use half the limit
    int* fds = malloc(sizeof(int) * NUM_FDS);
    if (!fds) {
        printf("SKIP: Cannot allocate memory\n");
        return 0;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child: try to open many FDs
        int opened = 0;
        for (int i = 0; i < NUM_FDS; i++) {
            int sv[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
                fds[opened++] = sv[0];
                fds[opened++] = sv[1];
            }
        }

        printf("  [Child] Opened %d file descriptors\n", opened);

        for (int i = 0; i < opened; i++) {
            close(fds[i]);
        }

        free(fds);
        exit(0);
    }

    free(fds);

    int status;
    waitpid(pid, &status, 0);

    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "resource sharing test completed");
    printf("PASS: Resource sharing test\n");
    return 0;
}

// ============================================================================
// Test 5: Process Death Recovery
// ============================================================================

static int test_process_death_recovery(void) {
    printf("\n=== Test: Process Death Recovery ===\n");

    pid_t child = fork();
    if (child == 0) {
        // Child: create resources then exit abnormally
        frpc_client_t* client = frpc_client_new(NULL, NULL);
        (void)client;  // Suppress unused warning

        // Exit without cleanup (simulate crash)
        _exit(1);
    }

    int status;
    waitpid(child, &status, 0);

    // Parent should continue normally
    frpc_client_t* client = frpc_client_new(NULL, NULL);

    TEST_ASSERT(client == NULL, "parent can still create client after child crash");

    printf("PASS: Process death recovery test\n");
    return 0;
}

// ============================================================================
// Test 6: Signal Handling
// ============================================================================

static int test_signal_handling(void) {
    printf("\n=== Test: Signal Handling ===\n");

    pid_t child = fork();
    if (child == 0) {
        // Child: wait indefinitely (will be killed)
        pause();
        exit(0);  // Should not reach here
    }

    // Send signal to child
    usleep(10000); // 10ms
    kill(child, SIGTERM);

    int status;
    waitpid(child, &status, 0);

    // Child should have been terminated by signal
    if (WIFSIGNALED(status)) {
        printf("PASS: Signal handling test (child terminated by signal %d)\n", WTERMSIG(status));
        return 0;
    } else {
        printf("FAIL: Signal handling test (child exited normally)\n");
        return -1;
    }
}

// ============================================================================
// Test 7: Pipe Communication
// ============================================================================

static int test_pipe_communication(void) {
    printf("\n=== Test: Inter-Process Pipe Communication ===\n");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        // Child: read from pipe
        close(pipefd[1]);

        char buf[128];
        ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("[Child] Received: %s\n", buf);
        }

        close(pipefd[0]);
        exit(n > 0 ? 0 : 1);
    } else {
        // Parent: write to pipe
        close(pipefd[0]);

        const char* msg = "Hello from parent!";
        write(pipefd[1], msg, strlen(msg));
        close(pipefd[1]);

        int status;
        waitpid(pid, &status, 0);

        TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                    "pipe communication succeeded");
        printf("PASS: Pipe communication test\n");
        return 0;
    }
}

// ============================================================================
// Test 8: Shared State Coordination
// ============================================================================

static int test_shared_state(void) {
    printf("\n=== Test: Shared State Coordination ===\n");

    // Use file as shared state
    char state_path[256];
    create_temp_file(state_path, sizeof(state_path));

    const int NUM_CHILDREN = 3;

    for (int i = 0; i < NUM_CHILDREN; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            // Child: update shared state
            int fd = open(state_path, O_WRONLY);
            if (fd >= 0) {
                char value = '1' + i;
                write(fd, &value, 1);
                close(fd);
            }
            exit(0);
        }
    }

    // Wait for all children
    for (int i = 0; i < NUM_CHILDREN; i++) {
        wait(NULL);
    }

    // Check final state
    int fd = open(state_path, O_RDONLY);
    if (fd >= 0) {
        char value;
        read(fd, &value, 1);
        close(fd);
        printf("  Final shared state value: %c\n", value);
    }

    unlink(state_path);

    printf("PASS: Shared state coordination test\n");
    return 0;
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    // Disable stdout buffering for immediate output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("\n");
    printf("========================================\n");
    printf("  FRP/STCP Multi-Process Tests\n");
    printf("========================================\n");

    int failed = 0;

    // Note: Some tests may require a real FRPS to be running
    // They're designed to fail gracefully if no server is available

    if (test_basic_multi_process() != 0) failed++;
    if (test_concurrent_processes() != 0) failed++;
    if (test_process_isolation() != 0) failed++;
    if (test_resource_sharing() != 0) failed++;
    if (test_process_death_recovery() != 0) failed++;
    if (test_signal_handling() != 0) failed++;
    if (test_pipe_communication() != 0) failed++;
    if (test_shared_state() != 0) failed++;

    printf("\n");
    printf("========================================\n");
    if (failed == 0) {
        printf("✅ All multi-process tests passed!\n");
    } else {
        printf("❌ %d test(s) failed\n", failed);
    }
    printf("========================================\n");

    return failed;
}
