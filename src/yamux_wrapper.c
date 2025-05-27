#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yamux.h"
#include "frpc_internal.h"

/**
 * @brief Write all data to a yamux stream
 * 
 * This function ensures that all data is written to the stream,
 * making multiple calls to yamux_write if necessary.
 * 
 * @param stream Yamux stream to write to
 * @param buffer Buffer containing data to write
 * @param length Total number of bytes to write
 * @return Number of bytes written, or -1 on error
 */
int yamux_write_all(void *stream, const uint8_t *buffer, size_t length) {
    if (!stream || !buffer || length == 0) {
        return -1;
    }
    
    size_t remaining = length;
    size_t offset = 0;
    
    while (remaining > 0) {
        int n = yamux_write(stream, buffer + offset, remaining);
        if (n <= 0) {
            /* Error or no progress, fail */
            return -1;
        }
        
        remaining -= n;
        offset += n;
    }
    
    return (int)length;
}
