//
// Created by JiFan on 2020/12/6.
//
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <winsock.h>
#include <unistd.h>
#include "time.h"
#include "sys/time.h"

int frpc_hal_get_tick(){
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // calculate milliseconds
    return (unsigned short)milliseconds;
};

int frpc_hal_create_tcp(char* ip, int port){
    WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2 ,2), &wsaData);
	if (iResult != 0) {
		printf("error at WSASturtup\n");
		return 0;
	}

    int h;
    h = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (h < 0) {
        closesocket(h);
        return 0;
    }

    struct sockaddr_in sad;
    memset(&sad, 0, sizeof(sad));
    sad.sin_family = AF_INET;
    sad.sin_addr.s_addr = inet_addr(ip);
    sad.sin_port = htons(port);
    if (connect(h, (struct sockaddr *) &sad, sizeof(sad)) < 0) {
        closesocket(h);
        return 0;
    }

    return h;
};

int frpc_hal_tcp_write(int h, char *buf, int size, int timeout_ms){
    struct timeval tv;
    tv.tv_sec = timeout_ms/1000;
    tv.tv_usec = (timeout_ms%1000)*1000;
    setsockopt(h, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv);
    if (send(h, buf, size, 0) != size) {
        closesocket(h);
        return 0;
    }
    return size;
};

int frpc_hal_tcp_read(int h, char *buf, int size, int timeout_ms){
    struct timeval tv;
    tv.tv_sec = timeout_ms/1000;
    tv.tv_usec = (timeout_ms%1000)*1000;
    setsockopt(h, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv);
    int bytes_recv = recv(h, buf, size - 1, 0);
    if (bytes_recv < 0 ){
        closesocket(h);
        return 0;
    }
    return bytes_recv;
};

void frpc_hal_tcp_close(int h){
    closesocket(h);
};
