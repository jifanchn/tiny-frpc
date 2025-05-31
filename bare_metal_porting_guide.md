# tiny-frpc Embedded System Porting Guide

## Overview

This guide provides detailed instructions on how to port tiny-frpc to various embedded systems, including FreeRTOS, bare metal systems, and adaptation to various network stacks.

## Porting Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                 Application Layer                       │
│              (Shell command processing, etc.)          │
└─────────────────────────────────────────────────────────┘
                            ↕
┌─────────────────────────────────────────────────────────┐
│                tiny-frpc API                           │
│         (frpc_init, frpc_process, etc.)                │
└─────────────────────────────────────────────────────────┘
                            ↕
┌─────────────────────────────────────────────────────────┐
│               Porting Adaptation Layer                  │
│      (Network I/O callbacks, memory management,        │
│                  time functions)                        │
└─────────────────────────────────────────────────────────┘
                            ↕
┌─────────────────────────────────────────────────────────┐
│             Hardware Abstraction Layer                  │
│      (Network stack, RTOS/bare metal, hardware         │
│                    drivers)                             │
└─────────────────────────────────────────────────────────┘
```

## Core Porting Points

### 1. Network I/O Interface Adaptation

This is the most critical part of porting, requiring implementation of two callback functions:

```c
// Network read callback
int your_net_read(void *ctx, uint8_t *buf, size_t len) {
    // Implement according to your network stack:
    // - lwIP: netconn_recv() or raw API
    // - uIP: handle uip_newdata() events
    // - Vendor network library: call corresponding receive function
    // - Direct hardware operation: read from network chip registers
    
    // Return values:
    // > 0: actual bytes read
    // = 0: no data available (non-blocking)
    // < 0: error
}

// Network write callback
int your_net_write(void *ctx, const uint8_t *buf, size_t len) {
    // Implement data transmission according to your network stack
    
    // Return values:
    // > 0: actual bytes written
    // = 0: buffer full, retry later
    // < 0: error
}
```

### 2. Common Network Stack Adaptation Examples

#### 2.1 lwIP Adaptation (Most Common)

```c
#include "lwip/netconn.h"
#include "lwip/api.h"

typedef struct {
    struct netconn *conn;
    struct netbuf *inbuf;
    void *data;
    u16_t len;
    u16_t offset;
} lwip_ctx_t;

int lwip_frpc_read(void *ctx, uint8_t *buf, size_t len) {
    lwip_ctx_t *lwip_ctx = (lwip_ctx_t *)ctx;
    
    // If there's cached data, read from cache first
    if (lwip_ctx->data && lwip_ctx->offset < lwip_ctx->len) {
        u16_t copy_len = lwip_ctx->len - lwip_ctx->offset;
        if (copy_len > len) copy_len = len;
        
        memcpy(buf, (uint8_t*)lwip_ctx->data + lwip_ctx->offset, copy_len);
        lwip_ctx->offset += copy_len;
        
        if (lwip_ctx->offset >= lwip_ctx->len) {
            netbuf_delete(lwip_ctx->inbuf);
            lwip_ctx->inbuf = NULL;
            lwip_ctx->data = NULL;
            lwip_ctx->offset = 0;
        }
        
        return copy_len;
    }
    
    // Receive new data
    err_t err = netconn_recv(lwip_ctx->conn, &lwip_ctx->inbuf);
    if (err != ERR_OK) {
        if (err == ERR_WOULDBLOCK) {
            return 0; // No data available
        }
        return -1; // Error
    }
    
    // Get data pointer
    netbuf_data(lwip_ctx->inbuf, &lwip_ctx->data, &lwip_ctx->len);
    lwip_ctx->offset = 0;
    
    // Copy data
    u16_t copy_len = lwip_ctx->len;
    if (copy_len > len) copy_len = len;
    
    memcpy(buf, lwip_ctx->data, copy_len);
    lwip_ctx->offset = copy_len;
    
    return copy_len;
}

int lwip_frpc_write(void *ctx, const uint8_t *buf, size_t len) {
    lwip_ctx_t *lwip_ctx = (lwip_ctx_t *)ctx;
    
    err_t err = netconn_write(lwip_ctx->conn, buf, len, NETCONN_COPY);
    if (err != ERR_OK) {
        if (err == ERR_WOULDBLOCK) {
            return 0; // Buffer full
        }
        return -1; // Error
    }
    
    return len;
}
```

#### 2.2 uIP Adaptation

```c
#include "uip.h"

typedef struct {
    uint8_t *rx_buffer;
    size_t rx_buffer_size;
    size_t rx_data_len;
    size_t rx_offset;
} uip_ctx_t;

int uip_frpc_read(void *ctx, uint8_t *buf, size_t len) {
    uip_ctx_t *uip_ctx = (uip_ctx_t *)ctx;
    
    // Check for new data
    if (uip_newdata()) {
        // Copy data to internal buffer
        size_t data_len = uip_datalen();
        if (data_len > uip_ctx->rx_buffer_size) {
            data_len = uip_ctx->rx_buffer_size;
        }
        
        memcpy(uip_ctx->rx_buffer, uip_appdata, data_len);
        uip_ctx->rx_data_len = data_len;
        uip_ctx->rx_offset = 0;
    }
    
    // Read data from buffer
    if (uip_ctx->rx_offset < uip_ctx->rx_data_len) {
        size_t copy_len = uip_ctx->rx_data_len - uip_ctx->rx_offset;
        if (copy_len > len) copy_len = len;
        
        memcpy(buf, uip_ctx->rx_buffer + uip_ctx->rx_offset, copy_len);
        uip_ctx->rx_offset += copy_len;
        
        return copy_len;
    }
    
    return 0; // No data available
}

int uip_frpc_write(void *ctx, const uint8_t *buf, size_t len) {
    // uIP transmission requires calling at appropriate times
    if (uip_acked() || uip_rexmit() || uip_newdata() || 
        uip_connected() || uip_poll()) {
        
        // Limit transmission length
        size_t send_len = len;
        if (send_len > uip_mss()) {
            send_len = uip_mss();
        }
        
        memcpy(uip_appdata, buf, send_len);
        uip_send(uip_appdata, send_len);
        
        return send_len;
    }
    
    return 0; // Cannot send temporarily
}
```

#### 2.3 Vendor Network Library Adaptation Example (Using a WiFi Module)

```c
// Assume there's a WiFi module providing the following APIs:
// - wifi_socket_read(socket_id, buffer, length)
// - wifi_socket_write(socket_id, buffer, length)

typedef struct {
    int socket_id;
    uint8_t temp_buffer[1024];
    size_t temp_len;
    size_t temp_offset;
} wifi_module_ctx_t;

int wifi_frpc_read(void *ctx, uint8_t *buf, size_t len) {
    wifi_module_ctx_t *wifi_ctx = (wifi_module_ctx_t *)ctx;
    
    // First read from temporary buffer
    if (wifi_ctx->temp_offset < wifi_ctx->temp_len) {
        size_t copy_len = wifi_ctx->temp_len - wifi_ctx->temp_offset;
        if (copy_len > len) copy_len = len;
        
        memcpy(buf, wifi_ctx->temp_buffer + wifi_ctx->temp_offset, copy_len);
        wifi_ctx->temp_offset += copy_len;
        
        return copy_len;
    }
    
    // Read new data from WiFi module
    int ret = wifi_socket_read(wifi_ctx->socket_id, 
                              wifi_ctx->temp_buffer, 
                              sizeof(wifi_ctx->temp_buffer));
    
    if (ret <= 0) {
        return ret; // No data or error
    }
    
    wifi_ctx->temp_len = ret;
    wifi_ctx->temp_offset = 0;
    
    // Copy data to caller
    size_t copy_len = wifi_ctx->temp_len;
    if (copy_len > len) copy_len = len;
    
    memcpy(buf, wifi_ctx->temp_buffer, copy_len);
    wifi_ctx->temp_offset = copy_len;
    
    return copy_len;
}

int wifi_frpc_write(void *ctx, const uint8_t *buf, size_t len) {
    wifi_module_ctx_t *wifi_ctx = (wifi_module_ctx_t *)ctx;
    
    return wifi_socket_write(wifi_ctx->socket_id, buf, len);
}
```

### 3. Memory Management Adaptation

#### 3.1 Using System malloc/free (if available)

```c
// By default, tiny-frpc uses standard malloc/free
// No additional configuration needed
```

#### 3.2 Custom Memory Allocator

```c
#include "your_memory_pool.h"

void* custom_malloc(size_t size) {
    return memory_pool_alloc(size);
}

void custom_free(void* ptr) {
    memory_pool_free(ptr);
}

// Set during initialization
int main(void) {
    frpc_set_allocators(custom_malloc, custom_free);
    // ... other initialization
}
```

#### 3.3 Static Memory Pool Example

```c
#define MEMORY_POOL_SIZE 8192
static uint8_t memory_pool[MEMORY_POOL_SIZE];
static size_t memory_used = 0;

void* static_malloc(size_t size) {
    // Simple linear allocator
    if (memory_used + size > MEMORY_POOL_SIZE) {
        return NULL; // Out of memory
    }
    
    void* ptr = &memory_pool[memory_used];
    memory_used += size;
    
    return ptr;
}

void static_free(void* ptr) {
    // Simple allocator doesn't support deallocation
    // Or implement a more complex memory management algorithm
}
```

### 4. RTOS Integration

#### 4.1 FreeRTOS Integration

```c
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

typedef struct {
    // Network related
    void *net_handle;
    
    // Synchronization objects
    SemaphoreHandle_t net_mutex;
    QueueHandle_t cmd_queue;
    
    // Task handles
    TaskHandle_t frpc_task;
    TaskHandle_t shell_task;
} frpc_rtos_ctx_t;

// FRPC processing task
void frpc_task_function(void *pvParameters) {
    frpc_rtos_ctx_t *ctx = (frpc_rtos_ctx_t *)pvParameters;
    
    while (1) {
        // Process FRPC events
        frpc_process(ctx->frpc_handle);
        
        // Yield CPU time
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// Shell command processing task
void shell_task_function(void *pvParameters) {
    frpc_rtos_ctx_t *ctx = (frpc_rtos_ctx_t *)pvParameters;
    shell_command_t cmd;
    
    while (1) {
        // Wait for commands
        if (xQueueReceive(ctx->cmd_queue, &cmd, portMAX_DELAY) == pdTRUE) {
            // Process command
            process_shell_command(&cmd);
        }
    }
}

// Initialize RTOS integration
int init_frpc_rtos(frpc_rtos_ctx_t *ctx) {
    // Create synchronization objects
    ctx->net_mutex = xSemaphoreCreateMutex();
    ctx->cmd_queue = xQueueCreate(10, sizeof(shell_command_t));
    
    if (!ctx->net_mutex || !ctx->cmd_queue) {
        return -1;
    }
    
    // Create tasks
    if (xTaskCreate(frpc_task_function, "frpc", 
                   configMINIMAL_STACK_SIZE * 2, ctx, 
                   tskIDLE_PRIORITY + 2, &ctx->frpc_task) != pdPASS) {
        return -1;
    }
    
    if (xTaskCreate(shell_task_function, "shell", 
                   configMINIMAL_STACK_SIZE, ctx, 
                   tskIDLE_PRIORITY + 1, &ctx->shell_task) != pdPASS) {
        return -1;
    }
    
    return 0;
}
```

#### 4.2 RT-Thread Integration

```c
#include <rtthread.h>

static rt_thread_t frpc_thread = RT_NULL;
static rt_mq_t shell_mq = RT_NULL;

void frpc_thread_entry(void *parameter) {
    void *frpc_handle = (void *)parameter;
    
    while (1) {
        frpc_process(frpc_handle);
        rt_thread_mdelay(10);
    }
}

int init_frpc_rtthread(void *frpc_handle) {
    // Create message queue
    shell_mq = rt_mq_create("shell_mq", 128, 10, RT_IPC_FLAG_FIFO);
    if (shell_mq == RT_NULL) {
        return -1;
    }
    
    // Create FRPC processing thread
    frpc_thread = rt_thread_create("frpc", frpc_thread_entry, 
                                  frpc_handle, 2048, 20, 20);
    if (frpc_thread == RT_NULL) {
        return -1;
    }
    
    rt_thread_startup(frpc_thread);
    
    return 0;
}
```

### 5. Bare Metal Implementation

#### 5.1 State Machine Approach

```c
typedef enum {
    FRPC_STATE_INIT,
    FRPC_STATE_CONNECTING,
    FRPC_STATE_CONNECTED,
    FRPC_STATE_PROCESSING,
    FRPC_STATE_ERROR
} frpc_state_t;

typedef struct {
    frpc_state_t state;
    void *frpc_handle;
    uint32_t last_process_time;
    uint32_t process_interval;
} frpc_bare_metal_ctx_t;

void frpc_state_machine(frpc_bare_metal_ctx_t *ctx) {
    uint32_t current_time = get_system_tick();
    
    switch (ctx->state) {
        case FRPC_STATE_INIT:
            // Initialize network connection
            if (init_network_connection() == 0) {
                ctx->state = FRPC_STATE_CONNECTING;
            }
            break;
            
        case FRPC_STATE_CONNECTING:
            // Wait for connection establishment
            if (is_network_connected()) {
                ctx->state = FRPC_STATE_CONNECTED;
            }
            break;
            
        case FRPC_STATE_CONNECTED:
            // Start FRPC client
            if (frpc_start(ctx->frpc_handle) == 0) {
                ctx->state = FRPC_STATE_PROCESSING;
                ctx->last_process_time = current_time;
            } else {
                ctx->state = FRPC_STATE_ERROR;
            }
            break;
            
        case FRPC_STATE_PROCESSING:
            // Process FRPC events periodically
            if (current_time - ctx->last_process_time >= ctx->process_interval) {
                if (frpc_process(ctx->frpc_handle) < 0) {
                    ctx->state = FRPC_STATE_ERROR;
                } else {
                    ctx->last_process_time = current_time;
                }
            }
            break;
            
        case FRPC_STATE_ERROR:
            // Error handling and reconnection
            reset_network_connection();
            ctx->state = FRPC_STATE_INIT;
            break;
    }
}

// Main loop
int main(void) {
    frpc_bare_metal_ctx_t ctx;
    
    // System initialization
    system_init();
    network_init();
    
    // FRPC initialization
    init_frpc_bare_metal(&ctx);
    
    while (1) {
        // Run state machine
        frpc_state_machine(&ctx);
        
        // Handle other system tasks
        handle_other_tasks();
        
        // Simple delay or enter low power mode
        delay_ms(10);
    }
}
```

### 6. Shell Command Processing Implementation

#### 6.1 Command Parser

```c
typedef struct {
    const char *name;
    int (*handler)(int argc, char *argv[], char *response, size_t response_size);
    const char *help;
} shell_command_t;

// Command handler function examples
int cmd_gpio(int argc, char *argv[], char *response, size_t response_size) {
    if (argc < 3) {
        snprintf(response, response_size, 
                "Usage: gpio <read|write> <pin> [value]\n");
        return -1;
    }
    
    int pin = atoi(argv[2]);
    
    if (strcmp(argv[1], "read") == 0) {
        int value = gpio_read(pin);
        snprintf(response, response_size, "GPIO %d = %d\n", pin, value);
    } else if (strcmp(argv[1], "write") == 0 && argc >= 4) {
        int value = atoi(argv[3]);
        gpio_write(pin, value);
        snprintf(response, response_size, "GPIO %d set to %d\n", pin, value);
    } else {
        snprintf(response, response_size, "Invalid gpio command\n");
        return -1;
    }
    
    return 0;
}

int cmd_sensor(int argc, char *argv[], char *response, size_t response_size) {
    float temp = read_temperature();
    float humidity = read_humidity();
    
    snprintf(response, response_size,
            "Temperature: %.1f°C\nHumidity: %.1f%%\n",
            temp, humidity);
    
    return 0;
}

// Command table
static const shell_command_t commands[] = {
    {"gpio", cmd_gpio, "GPIO operations"},
    {"sensor", cmd_sensor, "Read sensor data"},
    {"help", cmd_help, "Show help"},
    {NULL, NULL, NULL}
};

// Command parsing and execution
int execute_command(const char *cmd_line, char *response, size_t response_size) {
    char *argv[16];
    int argc = 0;
    char *cmd_copy = strdup(cmd_line);
    
    // Parse command line
    char *token = strtok(cmd_copy, " \t\n");
    while (token && argc < 15) {
        argv[argc++] = token;
        token = strtok(NULL, " \t\n");
    }
    argv[argc] = NULL;
    
    if (argc == 0) {
        free(cmd_copy);
        return 0;
    }
    
    // Find command
    for (int i = 0; commands[i].name; i++) {
        if (strcmp(commands[i].name, argv[0]) == 0) {
            int ret = commands[i].handler(argc, argv, response, response_size);
            free(cmd_copy);
            return ret;
        }
    }
    
    snprintf(response, response_size, 
            "Unknown command: %s\nType 'help' for available commands.\n", 
            argv[0]);
    
    free(cmd_copy);
    return -1;
}
```

### 7. Configuration Optimization

#### 7.1 Memory Optimization

```c
// Define at compile time to reduce memory usage
#define FRPC_MAX_PROXIES 2           // Maximum number of proxies
#define FRPC_BUFFER_SIZE 1024        // Buffer size
#define FRPC_MAX_CONNECTIONS 1       // Maximum connections

// Disable unnecessary features
#define FRPC_DISABLE_HTTP_PROXY      // Disable HTTP proxy
#define FRPC_DISABLE_UDP_PROXY       // Disable UDP proxy
```

#### 7.2 Performance Optimization

```c
// Adjust heartbeat interval
frpc_config_t config = {
    .heartbeat_interval = 60,    // Increase interval to reduce network traffic
    .heartbeat_timeout = 180,    // Correspondingly increase timeout
};

// Use non-blocking mode
// Ensure network I/O callback functions don't block
```

### 8. Debugging and Troubleshooting

#### 8.1 Enable Debug Output

```c
// Enable debug mode
frpc_set_debug(frpc_handle, 1);

// Add custom logging function
void debug_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
#ifdef DEBUG
    vprintf(format, args);
#endif
    
    va_end(args);
}
```

#### 8.2 Common Problem Troubleshooting

1. **Connection Failure**: Check network configuration and frps server address
2. **Out of Memory**: Reduce buffer sizes or use static memory allocation
3. **Data Loss**: Check implementation of network I/O callback functions
4. **Heartbeat Timeout**: Adjust heartbeat interval or check network stability

### 9. Complete Porting Checklist

- [ ] Implement network I/O callback functions
- [ ] Adapt memory management (if needed)
- [ ] Integrate with RTOS or implement bare metal state machine
- [ ] Implement shell command processor
- [ ] Configure proxy parameters
- [ ] Test basic connection functionality
- [ ] Test command send/receive functionality
- [ ] Optimize performance and memory usage
- [ ] Add error handling and reconnection mechanism
- [ ] Add debugging and logging functionality

This guide covers the key points for porting tiny-frpc to various embedded platforms. Choose the appropriate approach based on your specific hardware platform and requirements. 