/**
 * Simple HTTP server application
 *
 * @author: Pavel Kratochvil (xkrato61)
 *
 * @file hinfosvc.c
 *
 * @brief listens on a given port and responds to client requests
 */
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>

#include "errno.h"

#define CONN_LIM 5          // backlog, maximum number of pending connections
#define BUFFER_SIZE 1024    // used for incoming data from client, response message length, reading from fptr

char *response; // pointer to header+message to be sent back
int new_socket; // fd of socket of newly accepted connection
long port;      // program argument, port to listen on

// HTTP response struct, stores status code and message to be sent
struct HTTP_resp {
    uint res_code;
    char res_msg[BUFFER_SIZE];
};

struct HTTP_resp http_resp;

// prints error message
// returns param err_n
int handle_error(const int err_n) {
    switch (err_n) {
        case ERROR_SOCK:
            fprintf(stderr, "ERROR: Socket creation failed.\n");
            return ERROR_SOCK;
        case ERROR_BIND:
            fprintf(stderr, "ERROR: Binding failed.\n");
            return ERROR_BIND;
        case ERROR_LIS:
            fprintf(stderr, "ERROR: Listening failed.\n");
            return ERROR_LIS;
        case ERROR_ACC:
            fprintf(stderr, "ERROR: Accepting failed.\n");
            return ERROR_ACC;
        case ERROR_RD:
            fprintf(stderr, "ERROR: No bytes were read.\n");
            return ERROR_RD;
        case ERROR_CPU:
            fprintf(stderr, "ERROR: Reading CPU name failed.\n");
            return ERROR_CPU;
        case ERROR_MEM:
            fprintf(stderr, "ERROR: Unable to allocate memory.\n");
            return ERROR_MEM;
        case ERROR_NAME:
            fprintf(stderr, "ERROR: Reading hostname failed.\n");
            return ERROR_NAME;
        case ERROR_PARAM:
            fprintf(stderr, "ERROR: Invalid number of parameters.\n");
            return ERROR_PARAM;
        case ERROR_LOAD:
            fprintf(stderr, "ERROR: Reading cpu load failed.\n");
            return ERROR_LOAD;
        case ERROR_CLOSE:
            fprintf(stderr, "ERROR: Closing file stream failed.\n");
            return ERROR_CLOSE;
        default:
            return ERROR;
    }
}

// reads CPU info from fptr using popen()
// output is written to http_resp.res_msg struct field
// returns 0 on success, errno ERROR_NAME when reading failed
int cpu_name() {
    // creating fptr from shell command output
    FILE *cpu_name = popen("cat /proc/cpuinfo | grep \"model name\" | head -n 1 | awk '{split($0, str, \" \"); print str[4], str[5], str[6], str[7], str[8], str[9]}'", "r");
    // fptr check
    if(cpu_name == NULL) {
        return handle_error(ERROR_CPU);
    }
    // reading from fptr
    if(fgets(http_resp.res_msg, BUFFER_SIZE, cpu_name) == NULL) {
        return handle_error(ERROR_CPU);
    }
    http_resp.res_msg[strlen(http_resp.res_msg)-1] = '\0';

    //closing fptr
    if(pclose(cpu_name) != 0) {
        return ERROR_CLOSE;
    }

    return 0;
}

// reads hostname from fptr using popen()
// output is written to http_resp.res_msg struct field
// returns 0 on success, errno ERROR_NAME when reading failed
int host_name() {
    // creating fptr from shell command output
    FILE *hostname = popen("cat /etc/hostname", "r");
    // fptr check
    if(hostname == NULL) {
        return handle_error(ERROR_NAME);
    }
    // reading from fptr
    if(fgets(http_resp.res_msg, BUFFER_SIZE, hostname) == NULL) {
        return handle_error(ERROR_NAME);
    }
    http_resp.res_msg[strlen(http_resp.res_msg)-1] = '\0';

    // closing file ptr
    if(pclose(hostname) != 0) {
        return ERROR_CLOSE;
    }

    return 0;
}

// reads current cpu load from fptr using popen()
// writes output to param int_buff[]
// returns 0 on success, errno ERROR_LOAD when reading failed and ERROR_CLOSE when closing fptr failed
int cpu_load_reading(long int_buff[10]) {
    // local buffer for writing string values of cpu stats
    char buff[BUFFER_SIZE] = {'\0'};

    // creating fptr from shell command output
    FILE *cpu_first = popen("head -n1 /proc/stat | awk -F ' ' 'BEGIN{sum=0}{for(i=1;i < NF;i++){cpu_sum = sum += $i;printf(\"%d \", $i);}}END{}'", "r");
    // fptr check
    if(cpu_first == NULL) {
        return handle_error(ERROR_LOAD);
    }
    // reading from fptr
    if(fgets(buff, BUFFER_SIZE, cpu_first) == NULL) {
        return handle_error(ERROR_LOAD);
    }
    buff[strlen(buff)-1] = '\0';

    // closing file ptr
    if(pclose(cpu_first) != 0) {
        return ERROR_CLOSE;
    }

    // splitting output (delim: ' ')
    int i = 0;
    char *array[10] = {0};
    char *p = strtok (buff, " ");

    while (p != NULL) {
        array[i++] = p;
        p = strtok (NULL, " ");
    }

    // converting string output to integers
    for(i=0; i < 10; i++) {
        char *ptr = NULL;
        int_buff[i] = strtol(array[i], &ptr, 10);
        if(*ptr != '\0') {
            return handle_error(ERROR_LOAD);
        }
    }

    return 0;
}

// calls cpu_load_reading() twice to get current cpu usage, calculates current usage
// output is written to http_resp.res_msg struct field
// returns 0 on success, errno ERROR_RD when reading failed
int cpu_load() {
    // local buffers for calculations on output of cpu_load_readings()
    long first_read[10] = {0};
    long second_read[10] = {0};

    if(cpu_load_reading(first_read) < 0) {
        return handle_error(ERROR_RD);
    }

    // sleep between two reads
    sleep(1);

    if(cpu_load_reading(second_read) < 0) {
        return handle_error(ERROR_RD);
    }

    // summing cpu usage info from separate columns
    long cpu_sum_first = 0;
    long cpu_sum_second = 0;
    for(int i = 0; i < 10; i++) {
        cpu_sum_first += first_read[i];
        cpu_sum_second += second_read[i];
    }

    // delta between two reads
    long cpu_delta = cpu_sum_first - cpu_sum_second;
    // idle time delta
    long cpu_idle = first_read[4] - second_read[4];
    // calculate time spent working
    long cpu_used = cpu_delta - cpu_idle;
    // calculate percentage
    long cpu_usage = 100 * cpu_used / cpu_delta;

    // write cpu usage to http_resp.res_msg
    sprintf(http_resp.res_msg, "%ld%%", cpu_usage);

    return 0;
}

// parses domain in param char *buff, filters wrong domain requests
// returns 0 on success, 1 when domain was not found
// assigns http_resp.res_code, 200 OK, 500 Internal Error, 404 Not Found
int handle_request(const char *buff) {

    // copy requested domain into "domain" buffer
    // max needed length to compare is 14 (GET /hostname\0)
    int i = 0;
    char domain[15] = {0};
    int space_ctr = 0;
    while(space_ctr != 2 && i < 15) {
        domain[i] = buff[i];
        if(buff[i] == ' ') {
            space_ctr++;
        }
        i++;
    }
    domain[i - 1] = '\0';

    // get the response (cpu-name, hostname, cpu load)
    int result;
    if(!strcmp(domain, "GET /cpu-name")) {
        result = cpu_name();
    } else if(!strcmp(domain, "GET /load")) {
        result = cpu_load();
    } else if(!strcmp(domain, "GET /hostname")) {
        result = host_name();
    } else {
        // domain was not found
        http_resp.res_code = 400;
        return 1;
    }

    // assign HTTP response status code
    if(result < 0) {
        http_resp.res_code = 500;
    } else {
        http_resp.res_code = 200;
    }
    return 0;
}

// 200 OK template, reads data from http_resp struct
// returns errno ERROR_WRITE when writing to a socket failed, ERROR_SOCK when closing a socket failed
int respond_OK() {
    char *template = "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: %lu\n\n%s\n";
    // +1 for null byte
    response = malloc(sizeof(char) * (strlen(template) + strlen(http_resp.res_msg) + 1));
    // allocation check
    if(response == NULL) {
        return handle_error(ERROR_MEM);
    }
    // copying header+body to response
    sprintf(response, template, strlen(http_resp.res_msg), http_resp.res_msg);
    // writing to and closing socket
    if(write(new_socket, response, strlen(response)) < 0) {
        return handle_error(ERROR_WRITE);
    }
    if(close(new_socket) < 0) {
        return handle_error(ERROR_SOCK);
    }
    free(response);

    return 0;
}

// 500 Internal Server Error template
// returns errno ERROR_WRITE when writing to a socket failed, ERROR_SOCK when closing a socket failed
int respond_int_err() {
    char *template = "HTTP/1.1 500 Internal Error\nContent-Type: text/plain\nContent-Length: 18\n\n500 Internal error\n";
    // +1 for null byte
    response = malloc(sizeof(char) * (strlen(template) + 1));
    // allocation check
    if(response == NULL) {
        return handle_error(ERROR_MEM);
    }
    // copying header+body to response
    sprintf(response, "%s", template);
    // writing to and closing socket
    if(write(new_socket, response, strlen(response)) < 0) {
        return handle_error(ERROR_WRITE);
    }
    if(close(new_socket) < 0) {
        return handle_error(ERROR_SOCK);
    }
    free(response);

    return 0;
}

// 400 Bad Request template
// returns errno ERROR_WRITE when writing to a socket failed, ERROR_SOCK when closing a socket failed
int respond_bad_req() {
    char *template = "HTTP/1.1 400 Bad Request\nContent-Type: text/plain\nContent-Length: 15\n\n400 Bad Request\n";
    // +1 for null byte
    response = malloc(sizeof(char) * (strlen(template) + 1));
    // allocation check
    if(response == NULL) {
        return handle_error(ERROR_MEM);
    }
    // copying header+body to response
    sprintf(response, "%s", template);
    // writing to and closing socket
    if(write(new_socket, response, strlen(response)) < 0) {
        return handle_error(ERROR_WRITE);
    }
    if(close(new_socket) < 0) {
        return handle_error(ERROR_SOCK);
    }
    free(response);

    return 0;
}

// main function, parses arguments for port
// returns errno when serving request failed
int main(int argc, char *argv[]) {
    // argument checking
    if(argc == 1) {
        fprintf(stdout, "Usage: ./hinfosvc [PORT]\n"
                        "Example: ./hinfosvc 8080\n"
                        "Info: Simple http server listening on given port.\n"
                        "Possible requests:\n"
                        "   /hostname - machine hostname\n"
                        "   /cpu-name - CPU information\n"
                        "   /load     - current CPU load in %%\n");
    }
    if(argc != 2) {
        return handle_error(ERROR_PARAM);
    }
    char *p;
    port = strtol(argv[1], &p, 10);
    if(*p != '\0') {
        return ERROR_PARAM;
    }

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

    // clearing memory
    memset((char *)&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((int)port);

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

    // infinite new connection loop
    while(1) {

        // accepting connection and creating new socket
        new_socket = accept(server_fd, (struct sockaddr *) &address, (socklen_t *) &address_len);
        if (new_socket < 0) {
            return handle_error(ERROR_ACC);
        }

        // reading from socket
        char buffer[BUFFER_SIZE] = {0};
        long in_data = read(new_socket, buffer, BUFFER_SIZE);

        // read() returns: -1(error), 0(EOF), number of bytes read cannot exceed BUFFER_SIZE
        if (in_data <= 0) {
            handle_error(ERROR_RD);
            respond_bad_req();
            continue;
        }

        // handling request
        handle_request(buffer);

        // responding according to http_resp.res_code assigned in reading and handling functions
        switch(http_resp.res_code) {
            case 400:
                respond_bad_req();
                break;
            case 500:
                respond_int_err();
                break;
            case 200:
                respond_OK();
                break;
        }
    }
}
