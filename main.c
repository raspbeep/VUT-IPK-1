#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>

#define CONN_LIM 5
#define BUFFER_SIZE 1024

#define ERROR -1        // generic error
#define ERROR_SOCK -2   // unable to create socket
#define ERROR_BIND -3   // binding failed
#define ERROR_LIS -4    // listening failed
#define ERROR_ACC -5    // accepting failed
#define ERROR_RD -6     // reading failed
#define ERROR_PARAM -7  // wrong number of parameters
#define ERROR_CPU -8    // unable to read CPU name
#define ERROR_MEM -9    // allocation error
#define ERROR_NAME -10  // unable to read hostname
#define ERROR_LOAD -11  // cpu load reading failed

char *response;
int new_socket;
long port;

struct HTTP_resp {
    uint res_code;
    char res_msg[BUFFER_SIZE];
};

struct HTTP_resp http_resp;

int handle_error(int err_n) {
    switch (err_n) {
        case ERROR_SOCK:
            fprintf(stderr, "Socket creation failed.\n");
            return ERROR_SOCK;
        case ERROR_BIND:
            fprintf(stderr, "Binding failed.\n");
            return ERROR_BIND;
        case ERROR_LIS:
            fprintf(stderr, "Listening failed.\n");
            return ERROR_LIS;
        case ERROR_ACC:
            fprintf(stderr, "Accepting failed.\n");
            return ERROR_ACC;
        case ERROR_RD:
            close(new_socket);
            fprintf(stderr, "No bytes were read.\n");
            return ERROR_RD;
        case ERROR_CPU:
            fprintf(stderr, "Reading CPU name failed.\n");
            return ERROR_CPU;
        case ERROR_MEM:
            fprintf(stderr, "Unable to allocate memory.\n");
            return ERROR_MEM;
        case ERROR_NAME:
            fprintf(stderr, "Reading hostname failed.\n");
            return ERROR_NAME;
        case ERROR_PARAM:
            fprintf(stderr, "Invalid number of parameters.\n");
            return ERROR_PARAM;
        default:
            return ERROR;
    }
}

// finds cpu name and returns it in param buff
int cpu_name() {
    FILE *cpu_name = popen("cat /proc/cpuinfo | grep \"model name\" | head -n 1 | awk '{split($0, str, \" \"); print str[4], str[5], str[6], str[7], str[8], str[9]}'", "r");
    if(cpu_name == NULL) {
        return handle_error(ERROR_CPU);
    }

    if(fgets(http_resp.res_msg, BUFFER_SIZE, cpu_name) == NULL) {
        return handle_error(ERROR_CPU);
    }

    http_resp.res_msg[strlen(http_resp.res_msg)-1] = '\0';
    fclose(cpu_name);
//    if(fclose(cpu_name) != 0) {
//        // TODO: handle
//        return ERROR;
//    }
    http_resp.res_code = 200;
    return 0;
}

int host_name() {
    FILE *hostname = popen("cat /etc/hostname", "r");
    if(hostname == NULL) {
        return handle_error(ERROR_NAME);
    }

    if(fgets(http_resp.res_msg, BUFFER_SIZE, hostname) == NULL) {
        return handle_error(ERROR_NAME);
    }
    http_resp.res_msg[strlen(http_resp.res_msg)-1] = '\0';

    if(pclose(hostname) != 0) {
        // TODO: handle
        return ERROR;
    }
    http_resp.res_code = 200;
    return 0;
}

int cpu_load_reading(long int_buff[10]) {
    // local buffer for writing string values of cpu stats
    char buff[BUFFER_SIZE] = {'\0'};

    FILE *cpu_first = popen("head -n1 /proc/stat | awk -F ' ' 'BEGIN{sum=0}{for(i=1;i < NF;i++){cpu_sum = sum += $i;printf(\"%d \", $i);}}END{}'", "r");
    // allocation check
    if(cpu_first == NULL) {
        return handle_error(ERROR_LOAD);
    }
    // reading the result of shell command
    if(fgets(buff, BUFFER_SIZE, cpu_first) == NULL) {
        return handle_error(ERROR_LOAD);
    }
    buff[strlen(buff)-1] = '\0';

    int i = 0;
    char *p = strtok (buff, " ");
    char *array[10] = {0};

    while (p != NULL)
    {
        array[i++] = p;
        p = strtok (NULL, " ");
    }

    for(i=0; i < 10; i++) {
        char *ptr = NULL;
        int_buff[i] = strtol(array[i], &ptr, 10);
        if(*ptr != '\0') {
            return handle_error(ERROR_LOAD);
        }
    }

    fclose(cpu_first);
    return 0;
}

int cpu_load() {
    long first_read[10] = {0};
    long second_read[10] = {0};

    int result = cpu_load_reading(first_read);
    if(result < 0) {
        return handle_error(ERROR);
    }
    sleep(1);

    result = cpu_load_reading(second_read);
    if(result < 0) {
        return handle_error(ERROR);
    }

    long cpu_sum_first = 0;
    long cpu_sum_second = 0;

    for(int i = 0; i < 10; i++) {
        cpu_sum_first += first_read[i];
        cpu_sum_second += second_read[i];
    }

    long cpu_delta = cpu_sum_first - cpu_sum_second;
    long cpu_idle = first_read[4] - second_read[4];
    long cpu_used = cpu_delta - cpu_idle;
    long cpu_usage = 100 * cpu_used / cpu_delta;
    sprintf(http_resp.res_msg, "%ld%%", cpu_usage);
    http_resp.res_code = 200;

    return 0;
}

// finds the request in header and returns the beginning and end of domain part in header
int handle_request(const char *buff) {

    // copy requested domain into "domain" buffer
    int i = 0;
    char domain[14] = {0};
    int space_ctr = 0;
    while(space_ctr != 2) {
        domain[i] = buff[i];
        if(buff[i] == ' ') {
            space_ctr++;
        }
        i++;
    }
    domain[i - 1] = '\0';

    // get the response (cpu-name, hostname, cpu load)
    if(!strcmp(domain, "GET /cpu-name")) {
        if(cpu_name() < 0) {
            // TODO: handle
            return ERROR;
        }
    } else if(!strcmp(domain, "GET /load")) {
        if(cpu_load() < 0) {
            // TODO: handle
            return ERROR;
        }
    } else if(!strcmp(domain, "GET /hostname")) {
        if(host_name() < 0) {
            // TODO: handle
            return ERROR;
        }
    } else {
        http_resp.res_code = 400;
    }
    return 0;
}

int respond_OK() {
    uint template_len = 70;
    unsigned long msg_len = strlen(http_resp.res_msg);
    response = malloc(sizeof(char) * (template_len + msg_len) + 1);
    sprintf(response, "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: %lu\n\n%s\n", msg_len, http_resp.res_msg);

    write(new_socket, response, strlen(response));
    close(new_socket);
}

int respond_not_found() {

    sprintf(response, "HTTP/1.1 404 OK\nContent-Type: text/plain\nContent-Length: 13\n\n404 Not Found\n");
    write(new_socket, response, strlen(response));
    close(new_socket);
}

int respond_int_err() {

    sprintf(response, "HTTP/1.1 500 OK\nContent-Type: text/plain\nContent-Length: 18\n\n500 Internal error\n");
    write(new_socket, response, strlen(response));
    close(new_socket);
}

int respond_bad_req() {
    sprintf(response, "HTTP/1.1 400 OK\nContent-Type: text/plain\nContent-Length: 15\n\n400 Bad Request\n");
    write(new_socket, response, strlen(response));
    close(new_socket);
}


int main(int argc, char *argv[]) {

    if(argc != 2) {
        return handle_error(ERROR_PARAM);
    }

    char *p;
    port = strtol(argv[1], &p, 10);


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
            respond_not_found();
            continue;
        }

        // handling request
        int id_result = handle_request(buffer);

        if (id_result < 0) {
            // TODO: handle
            return handle_error(ERROR);
        }

        switch(http_resp.res_code) {
            case 400:
                respond_bad_req();
                break;
            case 401:
                respond_not_found();
                break;
            case 500:
                respond_int_err();
                break;
            case 200:
                respond_OK();
                break;
        }
    }
    return 0;
}
