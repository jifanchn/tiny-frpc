/**
 * @file embedded_stcp_shell_example.c
 * @brief Embedded System STCP Shell Remote Command Processing Example
 * 
 * This example demonstrates how to port tiny-frpc to FreeRTOS or bare metal systems,
 * implementing STCP server functionality to handle remote shell commands
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Include appropriate headers based on your embedded platform
#ifdef USE_FREERTOS
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#endif

#include "frpc.h"

/* =============================================================================
 * Embedded System Configuration and Abstraction Layer
 * ============================================================================= */

#define MAX_SHELL_BUFFER 512
#define MAX_RESPONSE_BUFFER 1024
#define FRPS_SERVER_PORT 7000
#define LOCAL_SHELL_PORT 22    // Simulate SSH port

/* Embedded system network interface abstraction */
typedef struct {
    /* Modify these fields according to your embedded network stack */
    int socket_fd;              // Or your network connection handle
    uint8_t *tx_buffer;         // Send buffer
    uint8_t *rx_buffer;         // Receive buffer
    size_t tx_buffer_size;
    size_t rx_buffer_size;
    volatile int connected;     // Connection status
    
#ifdef USE_FREERTOS
    SemaphoreHandle_t mutex;    // Mutex
#endif
} embedded_net_ctx_t;

/* Shell command processing context */
typedef struct {
    char command_buffer[MAX_SHELL_BUFFER];
    char response_buffer[MAX_RESPONSE_BUFFER];
    int (*command_handler)(const char *cmd, char *response, size_t response_size);
} shell_ctx_t;

/* STCP server context */
typedef struct {
    void *frpc_handle;
    embedded_net_ctx_t net_ctx;
    shell_ctx_t shell_ctx;
    volatile int running;
} stcp_server_ctx_t;

/* =============================================================================
 * Embedded System Network Interface Implementation
 * ============================================================================= */

/**
 * @brief Embedded system network read callback
 * Implement your network stack read function here
 */
static int embedded_net_read(void *ctx, uint8_t *buf, size_t len) {
    embedded_net_ctx_t *net_ctx = (embedded_net_ctx_t *)ctx;
    
    if (!net_ctx->connected) {
        return -1;
    }
    
#ifdef USE_FREERTOS
    // FreeRTOS version: use mutex protection
    if (xSemaphoreTake(net_ctx->mutex, portMAX_DELAY) == pdTRUE) {
#endif
        
        /* Implement data reading according to your network stack */
        /* Example: read data from network hardware or software stack */
        int bytes_read = 0;
        
        // Example implementation - replace with your network stack API
        // bytes_read = your_network_stack_read(net_ctx->socket_fd, buf, len);
        
        // Mock implementation: read from receive buffer
        if (net_ctx->rx_buffer && len > 0) {
            // This should be your specific network stack implementation
            bytes_read = 0; // Currently return 0 indicating no data
        }
        
#ifdef USE_FREERTOS
        xSemaphoreGive(net_ctx->mutex);
    }
#endif
    
    return bytes_read;
}

/**
 * @brief Embedded system network write callback
 * Implement your network stack write function here
 */
static int embedded_net_write(void *ctx, const uint8_t *buf, size_t len) {
    embedded_net_ctx_t *net_ctx = (embedded_net_ctx_t *)ctx;
    
    if (!net_ctx->connected || len == 0) {
        return -1;
    }
    
#ifdef USE_FREERTOS
    // FreeRTOS version: use mutex protection
    if (xSemaphoreTake(net_ctx->mutex, portMAX_DELAY) == pdTRUE) {
#endif
        
        /* Implement data writing according to your network stack */
        int bytes_written = 0;
        
        // Example implementation - replace with your network stack API
        // bytes_written = your_network_stack_write(net_ctx->socket_fd, buf, len);
        
        // Mock implementation: write to send buffer
        if (net_ctx->tx_buffer && len <= net_ctx->tx_buffer_size) {
            memcpy(net_ctx->tx_buffer, buf, len);
            bytes_written = len;
            // This should trigger your network hardware to send data
        }
        
#ifdef USE_FREERTOS
        xSemaphoreGive(net_ctx->mutex);
    }
#endif
    
    return bytes_written;
}

/* =============================================================================
 * Shell Command Processing System
 * ============================================================================= */

/**
 * @brief Simple shell command processor
 * Implement your embedded device command processing logic
 */
static int process_shell_command(const char *cmd, char *response, size_t response_size) {
    if (!cmd || !response || response_size == 0) {
        return -1;
    }
    
    // Clear response buffer
    memset(response, 0, response_size);
    
    /* Implement your command processing logic */
    if (strncmp(cmd, "help", 4) == 0) {
        snprintf(response, response_size,
            "Available commands:\n"
            "  help     - Show this help\n"
            "  status   - Show system status\n"
            "  version  - Show firmware version\n"
            "  reboot   - Reboot system\n"
            "  gpio     - GPIO operations\n"
            "  sensor   - Read sensor data\n");
            
    } else if (strncmp(cmd, "status", 6) == 0) {
        snprintf(response, response_size,
            "System Status:\n"
            "  CPU Usage: 45%%\n"
            "  Free Memory: 128KB\n"
            "  Uptime: 1234 seconds\n"
            "  Temperature: 35°C\n");
            
    } else if (strncmp(cmd, "version", 7) == 0) {
        snprintf(response, response_size,
            "Firmware Version: v1.2.3\n"
            "Build Date: %s %s\n"
            "tiny-frpc integrated\n", __DATE__, __TIME__);
            
    } else if (strncmp(cmd, "gpio", 4) == 0) {
        // Parse GPIO command (gpio read pin / gpio write pin value)
        char subcmd[16];
        int pin, value;
        
        if (sscanf(cmd, "gpio %s %d %d", subcmd, &pin, &value) >= 2) {
            if (strcmp(subcmd, "read") == 0) {
                // Read GPIO state
                int gpio_state = 0; // your_gpio_read(pin);
                snprintf(response, response_size, "GPIO %d = %d\n", pin, gpio_state);
            } else if (strcmp(subcmd, "write") == 0 && sscanf(cmd, "gpio write %d %d", &pin, &value) == 2) {
                // Write GPIO state
                // your_gpio_write(pin, value);
                snprintf(response, response_size, "GPIO %d set to %d\n", pin, value);
            } else {
                snprintf(response, response_size, "GPIO usage: gpio read <pin> | gpio write <pin> <value>\n");
            }
        } else {
            snprintf(response, response_size, "GPIO usage: gpio read <pin> | gpio write <pin> <value>\n");
        }
        
    } else if (strncmp(cmd, "sensor", 6) == 0) {
        // Read sensor data
        snprintf(response, response_size,
            "Sensor Data:\n"
            "  Temperature: 25.6°C\n"
            "  Humidity: 60.2%%\n"
            "  Pressure: 1013.25 hPa\n");
            
    } else if (strncmp(cmd, "reboot", 6) == 0) {
        snprintf(response, response_size, "System rebooting...\n");
        // In actual system, this would trigger a reboot
        // system_reboot();
        
    } else {
        snprintf(response, response_size, "Unknown command: %s\nType 'help' for available commands.\n", cmd);
    }
    
    return 0;
}

/* =============================================================================
 * STCP Visitor Callback Handling
 * ============================================================================= */

/**
 * @brief STCP Visitor state change callback
 * Called when a new visitor connects or disconnects
 */
static void stcp_visitor_callback(void *ctx, const char *proxy_name, 
                                const char *server_name, uint16_t bind_port, 
                                void *user_data) {
    stcp_server_ctx_t *server_ctx = (stcp_server_ctx_t *)user_data;
    
    if (server_name != NULL) {
        printf("[STCP] Visitor '%s' connected to server '%s' on port %d\n", 
               proxy_name, server_name, bind_port);
        
        /* In actual embedded system, you might need to:
         * 1. Allocate resources for this connection
         * 2. Prepare to handle connections from this visitor
         * 3. Update system state
         */
    } else {
        printf("[STCP] Visitor '%s' disconnected\n", proxy_name);
        
        /* Clean up resources */
    }
}

/**
 * @brief Handle new work connection
 * Called when a client connects to visitor port
 */
static int stcp_workconn_callback(void *ctx, const char *proxy_name,
                                void *client_conn, void *user_data) {
    stcp_server_ctx_t *server_ctx = (stcp_server_ctx_t *)user_data;
    
    printf("[STCP] New work connection for proxy '%s'\n", proxy_name);
    
    /* 
     * Handle connections from remote clients here
     * client_conn is the client connection handle, you need to:
     * 1. Read command data from client_conn
     * 2. Process commands
     * 3. Write responses back to client_conn
     */
    
    // Create a processing task to manage this connection
    // In FreeRTOS, you might want to create a new task
#ifdef USE_FREERTOS
    // xTaskCreate(handle_client_connection_task, "shell_client", 
    //             configMINIMAL_STACK_SIZE, client_conn, tskIDLE_PRIORITY + 1, NULL);
#endif
    
    return 0;
}

/* =============================================================================
 * Client Connection Handling
 * ============================================================================= */

/**
 * @brief Handle individual client shell session
 * This function processes commands from remote clients
 */
static void handle_shell_session(void *client_conn, shell_ctx_t *shell_ctx) {
    char *cmd_buffer = shell_ctx->command_buffer;
    char *resp_buffer = shell_ctx->response_buffer;
    
    /* 
     * In actual implementation, you need to:
     * 1. Read command data from client_conn
     * 2. Parse commands
     * 3. Call command processor
     * 4. Send responses back to client
     */
    
    // Mock reading command (should actually read from client_conn)
    // int bytes_read = read_from_client(client_conn, cmd_buffer, MAX_SHELL_BUFFER-1);
    
    // Example: assume received "status" command
    strcpy(cmd_buffer, "status");
    
    // Process command
    if (shell_ctx->command_handler) {
        shell_ctx->command_handler(cmd_buffer, resp_buffer, MAX_RESPONSE_BUFFER);
        
        // Send response back to client
        // write_to_client(client_conn, resp_buffer, strlen(resp_buffer));
        
        printf("[Shell] Command: %s\n", cmd_buffer);
        printf("[Shell] Response: %s\n", resp_buffer);
    }
}

#ifdef USE_FREERTOS
/**
 * @brief FreeRTOS task: handle client connection
 */
static void handle_client_connection_task(void *pvParameters) {
    void *client_conn = pvParameters;
    
    // Get shell context (in actual implementation, you need to pass this context)
    shell_ctx_t shell_ctx;
    shell_ctx.command_handler = process_shell_command;
    
    // Process client session
    handle_shell_session(client_conn, &shell_ctx);
    
    // Clean up and delete task
    vTaskDelete(NULL);
}
#endif

/* =============================================================================
 * STCP Server Initialization and Operation
 * ============================================================================= */

/**
 * @brief Initialize STCP server
 */
static int init_stcp_server(stcp_server_ctx_t *server_ctx, 
                           const char *frps_addr, const char *token) {
    // Initialize network context
    embedded_net_ctx_t *net_ctx = &server_ctx->net_ctx;
    
    // Allocate network buffers
    net_ctx->tx_buffer = malloc(1024);
    net_ctx->rx_buffer = malloc(1024);
    net_ctx->tx_buffer_size = 1024;
    net_ctx->rx_buffer_size = 1024;
    net_ctx->connected = 1; // Assume connected
    
    if (!net_ctx->tx_buffer || !net_ctx->rx_buffer) {
        printf("Memory allocation failed\n");
        return -1;
    }
    
#ifdef USE_FREERTOS
    // Create mutex
    net_ctx->mutex = xSemaphoreCreateMutex();
    if (net_ctx->mutex == NULL) {
        printf("Failed to create mutex\n");
        return -1;
    }
#endif
    
    // Configure frpc
    frpc_config_t config = {
        .server_addr = frps_addr,
        .server_port = FRPS_SERVER_PORT,
        .token = token,
        .user = "embedded_device",
        .heartbeat_interval = 30,
        .heartbeat_timeout = 90
    };
    
    // Initialize frpc
    server_ctx->frpc_handle = frpc_init(
        embedded_net_read, 
        embedded_net_write, 
        net_ctx, 
        &config
    );
    
    if (!server_ctx->frpc_handle) {
        printf("Failed to initialize frpc\n");
        return -1;
    }
    
    // Set visitor callbacks
    frpc_set_visitor_callbacks(
        server_ctx->frpc_handle,
        stcp_visitor_callback,
        stcp_workconn_callback,
        server_ctx
    );
    
    // Add STCP server proxy
    frpc_proxy_config_t proxy = {
        .name = "embedded_shell",
        .type = FRPC_PROXY_TYPE_STCP,
        .local_ip = "127.0.0.1",
        .local_port = LOCAL_SHELL_PORT,
        .sk = "embedded_device_secret_key_123456",
        .is_visitor = 0  // We are in server mode
    };
    
    if (frpc_add_proxy(server_ctx->frpc_handle, &proxy) < 0) {
        printf("Failed to add STCP proxy\n");
        return -1;
    }
    
    // Initialize shell processor
    server_ctx->shell_ctx.command_handler = process_shell_command;
    
    return 0;
}

/**
 * @brief Run STCP server main loop
 */
static void run_stcp_server(stcp_server_ctx_t *server_ctx) {
    // Start frpc client
    if (frpc_start(server_ctx->frpc_handle) < 0) {
        printf("Failed to start frpc client\n");
        return;
    }
    
    printf("STCP Shell Server started successfully\n");
    printf("Waiting for remote connections...\n");
    
    server_ctx->running = 1;
    
    // Main event loop
    while (server_ctx->running) {
        // Process frpc events
        frpc_process(server_ctx->frpc_handle);
        
        /* Other system tasks */
        
#ifdef USE_FREERTOS
        // In FreeRTOS, yield CPU time
        vTaskDelay(pdMS_TO_TICKS(10));
#else
        // In bare metal system, you might need other delay mechanisms
        // delay_ms(10);
#endif
    }
    
    printf("STCP Server shutting down\n");
}

/* =============================================================================
 * Main Program and Task Entry Points
 * ============================================================================= */

#ifdef USE_FREERTOS
/**
 * @brief FreeRTOS main task
 */
static void stcp_server_task(void *pvParameters) {
    stcp_server_ctx_t *server_ctx = (stcp_server_ctx_t *)pvParameters;
    
    // Run server
    run_stcp_server(server_ctx);
    
    // Clean up resources
    if (server_ctx->frpc_handle) {
        frpc_stop(server_ctx->frpc_handle);
        frpc_destroy(server_ctx->frpc_handle);
    }
    
    vTaskDelete(NULL);
}
#endif

/**
 * @brief Start embedded STCP Shell server
 */
int start_embedded_stcp_shell(const char *frps_addr, const char *token) {
    static stcp_server_ctx_t server_ctx;
    
    printf("Starting embedded STCP shell server...\n");
    printf("FRP Server: %s:%d\n", frps_addr, FRPS_SERVER_PORT);
    printf("Token: %s\n", token ? token : "none");
    
    // Initialize server
    if (init_stcp_server(&server_ctx, frps_addr, token) < 0) {
        printf("Failed to initialize STCP server\n");
        return -1;
    }
    
#ifdef USE_FREERTOS
    // Create STCP server task
    if (xTaskCreate(stcp_server_task, "stcp_server", 
                   configMINIMAL_STACK_SIZE * 4, &server_ctx, 
                   tskIDLE_PRIORITY + 2, NULL) != pdPASS) {
        printf("Failed to create STCP server task\n");
        return -1;
    }
    
    return 0;
#else
    // In bare metal system, run directly
    run_stcp_server(&server_ctx);
    return 0;
#endif
}

/**
 * @brief Example main function
 */
int main(void) {
    /* Embedded system initialization */
    // hardware_init();
    // network_stack_init();
    
#ifdef USE_FREERTOS
    /* FreeRTOS environment */
    // Start STCP Shell server
    start_embedded_stcp_shell("192.168.1.100", "my_device_token");
    
    // Start scheduler
    vTaskStartScheduler();
    
    // Should not reach here
    while(1);
    
#else
    /* Bare metal environment */
    printf("Embedded STCP Shell Server (Bare Metal)\n");
    
    // Start server directly (will block in main loop)
    start_embedded_stcp_shell("192.168.1.100", "my_device_token");
    
    return 0;
#endif
}

/* =============================================================================
 * Usage Instructions and Porting Guide
 * ============================================================================= 
 * 
 * 1. Network Interface Porting:
 *    - Modify embedded_net_read() and embedded_net_write() functions
 *    - Implement actual network I/O according to your network stack API
 *    - Possible network stacks: lwIP, uIP, or vendor-provided network libraries
 * 
 * 2. Memory Management:
 *    - Adjust buffer sizes if memory is limited
 *    - Consider using static memory pools instead of dynamic allocation
 *    - Use frpc_set_allocators() to set custom memory allocators if needed
 * 
 * 3. FreeRTOS Integration:
 *    - Adjust task stack sizes and priorities
 *    - Use appropriate synchronization mechanisms (semaphores, mutexes, etc.)
 *    - Consider inter-task communication (queues, event groups, etc.)
 * 
 * 4. Bare Metal Porting:
 *    - Remove FreeRTOS-related code
 *    - Implement simple task scheduling or state machine
 *    - Use interrupt-driven I/O processing
 * 
 * 5. Command Extension:
 *    - Add your device-specific commands in process_shell_command()
 *    - Implement GPIO, sensor, configuration operations
 *    - Add security checks and permission control
 * 
 * 6. Connection Management:
 *    - Implement connection timeout and reconnection mechanisms
 *    - Handle network disconnection recovery
 *    - Monitor connection status and quality
 * 
 * Usage Example:
 * 1. Configure STCP server (this code runs on embedded device)
 * 2. Configure STCP Visitor (runs on machine with public network access)
 * 3. Connect and send shell commands through Visitor port
 * 4. Device responds to commands and returns results
 * 
 * ============================================================================= */ 