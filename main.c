#include "frpc.h"
#include "yamux.h"
#include "wrapper.h"
#include <unistd.h>

void yamux_test(){
    char buf[1024];
    yamux y;
    yamux_init(&y);
    yamux_create_tcp(&y, "192.168.10.253", 4000);
    int s = yamux_create_stream(&y, buf);
    int count = 0;
    while(1){
        sleep(1);
        count = (count + 1) % 10;
        buf[13] = count;
        buf[14] = 1;
        buf[15] = 2;
        yamux_stream_send(&y, s, buf, 3);
    }
}

int main(){
    yamux_test();
}