#include "frpc.h"
#include "yamux.h"
#include "wrapper.h"
#include <unistd.h>
#include <stdio.h>

void yamux_test(){
    char buf[1024];
    char buf2[1024];
    yamux y;
    yamux_init(&y);
    yamux_create_tcp(&y, "192.168.10.253", 14000);
    int s = yamux_create_stream(&y, buf);
    buf[12] = 0;
    buf[13] = 1;
    buf[14] = 2;
    yamux_stream_send(&y, s, buf, 3);
    int count = 0;
    while(1){
        sleep(1);
        count = (count + 1) % 10;
        // yamux_stream_send(&y, s, buf, 3);
        int start;
        int n = yamux_tick(&y, buf, 1024, &start, buf2, 1024, 100);
        if (n > 0) {
            printf("receive data %d: ", n);
            for (int i = 0; i < n; i++) {
                printf(" %d", buf[12 + i]);
            }
            printf("\n");
            fflush(stdout);
        }
    }
}

int main(){
    yamux_test();
}