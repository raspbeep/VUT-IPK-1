#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>

#define PORT 8080
#define CONN_LIM 5
#define BUFFER_SIZE 1024

#define ERROR -1        // generic error
#define ERROR_SOCK -2   // unable to create socket
#define ERROR_BIND -3   // binding failed
#define ERROR_LIS -4    // listening failed
#define ERROR_ACC -5    // accepting failed
#define ERROR_RD -6     // reading failed
#define ERROR_HEADER -7 // unable to parse header
#define ERROR_CPU -8    // unable to read CPU name

int handle_error(int err_n) {
    switch (err_n) {
        case ERROR_SOCK:
            fprintf(stderr, "Socket creation failed.");
            return ERROR_SOCK;
        case ERROR_BIND:
            fprintf(stderr, "Binding failed.");
            return ERROR_BIND;
        case ERROR_LIS:
            fprintf(stderr, "Listening failed.");
            return ERROR_LIS;
        case ERROR_ACC:
            fprintf(stderr, "Accepting failed.");
            return ERROR_ACC;
        case ERROR_RD:
            fprintf(stderr, "No bytes were read.");
            return ERROR_RD;
        case ERROR_CPU:
            fprintf(stderr, "Reading CPU name failed.");
            return ERROR_CPU;
        default:
            return ERROR;
    }
}

// finds cpu name and returns it in param buff
int cpu_name(char buff[BUFFER_SIZE]) {
    FILE *cpu_name = popen("cat /proc/cpuinfo | grep \"model name\" | head -n 1 | awk '{split($0, str, \" \"); print str[4], str[5], str[6]}'", "r");
    if(cpu_name == NULL) {
        return handle_error(ERROR_CPU);
    }
    if(fgets(buff, BUFFER_SIZE, cpu_name) == NULL) {
        return handle_error(ERROR_CPU);
    }
    fclose(cpu_name);
    return 0;
}


// finds the request in header and returns the beginning and end of domain part in header
int identify_request(const char *buff, int *beg, int *end) {
    int pos_beg = 0;
    while(buff[pos_beg] != '/') {
        pos_beg++;
    }
    pos_beg++;

    int pos_end = pos_beg;
    while(buff[pos_end] != ' ') {
        pos_end++;
    }
    pos_end--;

    // length of the longest possible url part after /
    if(pos_end - pos_beg > 8) {
        return handle_error(ERROR_HEADER);
    }
    return 0;
}



int main() {

    // socket creation using a system call
    // domain options: AF_INET(IP), AF_INET6(IPv6)
    // type options: SOCK_STREAM(virtual circuit service), SOCK_RAW(direct IP service)
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt_val = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt_val, sizeof(opt_val));

    if (server_fd < 0) {
        return handle_error(ERROR_SOCK);
    }

    // setting the sock address struct
    struct sockaddr_in address;
    int address_len = sizeof(address);

    memset((char *)&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(PORT);

    // socket binding
    int bind_result = bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    if(bind_result < 0) {
        return handle_error(ERROR_BIND);
    }

    // setup listening
    int listen_result = listen(server_fd, CONN_LIM);
    if(listen_result < 0) {
        return handle_error(ERROR_LIS);
    }

    while(1) {
        // accepting connection and creating new socket

        int new_socket = accept(server_fd, (struct sockaddr *) &address, (socklen_t *) &address_len);
        printf("Accepted incoming connection!\n");
        if (new_socket < 0) {
            return handle_error(ERROR_ACC);
        }

        // reading from socket
        char buffer[BUFFER_SIZE] = {0};
        long in_data = read(new_socket, buffer, BUFFER_SIZE);
        if (in_data < 0) {
            return handle_error(ERROR_RD);
        }
        printf("%s",buffer);
        int beg, end;
        identify_request(buffer, &beg, &end);

        // writing to socket
        char *header = "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 12\n\nHello world!\n";
        char *message = "Hello World!";
        write(new_socket, header, strlen(header));
        printf("Message sent!\n");
        close(new_socket);
    }
    return 0;
}
