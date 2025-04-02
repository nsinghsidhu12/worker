#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <crypt.h>
#include <pthread.h>

#define NO_ARG_MESSAGE_LEN 128
#define UNKNOWN_OPTION_MESSAGE_LEN 64
#define BASE_TEN 10

pthread_mutex_t lock_checkpoint_count;
pthread_mutex_t lock_found_flag;

int checkpoint_count = 0;
int found_flag = 0;
int *thread_progress;
unsigned char **thread_last_attempt;
int *thread_last_attempt_size;
static volatile sig_atomic_t exit_flag = 0;

struct server_message {
    uint8_t total_size;
    uint8_t type;
    uint8_t node_num;
    uint8_t hash_size;
    char *hash;
    int work_size;
    int checkpoint;
    uint8_t password_space_size;
    unsigned char *password_space;
};

struct thread_data {
    int id;
    char *password_hash;
    char *prefix_salt;
    int work_size;
    int checkpoint;
    int split;
    int threads_num;
    int node_num;
    int socket_fd;
    int remaining;
    uint8_t password_space_size;
    unsigned char *password_space;
};

void parse_arguments(int argc, char *argv[], char **server_ip, char **port_str, char **threads_str);

void handle_arguments(char *program_name, char *server_ip, char *port_str, char *threads_str, in_port_t *port,
                      int *threads_num);

in_port_t parse_in_port_t(char *program_name, char *input);

int parse_int(char *program_name, char *input);

void convert_address(struct sockaddr_storage *socket_addr, char *ip_address);

int create_socket(int domain, int type, int protocol);

void connect_socket(int socket_fd, struct sockaddr_storage socket_addr, in_port_t port);

void close_socket(int socket_fd);

void ask_for_work(int socket_fd);

int get_work(int socket_fd, struct server_message *message);

ssize_t receive_message(int socket_fd, uint8_t **message);

char *extract_password_prefix_salt(char *program_name, char *password_hash);

int find_index_extract_till_nth_char(char *str, char c, int num, char *result);

void split_password_space(uint8_t **password_space, int *size, int limit);

void *crack_password(void *arg);

void send_update(int socket_fd, int node_num, int threads_num, int work_size);

void send_password(int socket_fd, int node_num, int password_space_size, unsigned char *password_space);

void send_disconnect(int socket_fd);

void print_thread_guess(int thread_id, int password_space_size, unsigned char *password_space);

void print_thread_subtasks(int threads_num);

void setup_signal_handler();

void sigint_handler(int signum);

void usage(char *program_name, int exit_code, char *message);

int main(int argc, char *argv[]) {
    char *server_ip;
    char *port_str;
    char *threads_str;

    in_port_t port;
    int threads_num;

    struct sockaddr_storage socket_addr;

    parse_arguments(argc, argv, &server_ip, &port_str, &threads_str);
    handle_arguments(argv[0], server_ip, port_str, threads_str, &port, &threads_num);

    thread_progress = (int *) malloc(threads_num * sizeof(int));

    if (thread_progress == NULL) {
        perror("Memory allocation failed");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < threads_num; i++) {
        thread_progress[i] = 0;
    }

    thread_last_attempt_size = (int *) malloc(threads_num * sizeof(int));

    if (thread_last_attempt_size == NULL) {
        perror("Memory allocation failed");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < threads_num; i++) {
        thread_last_attempt_size[i] = 0;
    }

    thread_last_attempt = (unsigned char **) malloc(threads_num * sizeof(unsigned char *));

    if (thread_last_attempt == NULL) {
        perror("Memory allocation failed");
        return EXIT_FAILURE;
    }

    convert_address(&socket_addr, server_ip);
    int socket_fd = create_socket(socket_addr.ss_family, SOCK_STREAM, 0);
    connect_socket(socket_fd, socket_addr, port);

    setup_signal_handler();

    pthread_mutex_init(&lock_checkpoint_count, NULL);
    pthread_mutex_init(&lock_found_flag, NULL);

    while (!found_flag && !exit_flag) {
        struct server_message *message = malloc(sizeof(struct server_message));

        if (message == NULL) {
            perror("Error allocating message");
            close_socket(socket_fd);
            exit(EXIT_FAILURE);
        }

        memset(message, 0, sizeof(struct server_message));

        ask_for_work(socket_fd);


        if (get_work(socket_fd, message) == -1) {
            free(message);
            break;
        }

        char *prefix_salt = extract_password_prefix_salt(argv[0], message->hash);

        int buckets[threads_num];
        int quotient = message->work_size / threads_num;
        int remainder = message->work_size % threads_num;
        int rem = message->work_size % message->checkpoint;

        for (int i = 0; i < threads_num; i++) {
            buckets[i] = quotient;
        }

        for (int i = 0; i < remainder; i++) {
            buckets[i] += 1;
        }

        pthread_t threads[threads_num];
        struct thread_data *thread_data = malloc(threads_num * sizeof(struct thread_data));

        for (int i = 0; i < threads_num; i++) {
            thread_data[i].id = i + 1;
            thread_data[i].password_hash = message->hash;
            thread_data[i].prefix_salt = prefix_salt;
            thread_data[i].work_size = message->work_size;
            thread_data[i].checkpoint = message->checkpoint;
            thread_data[i].password_space_size = message->password_space_size;
            thread_data[i].split = buckets[i];
            thread_data[i].threads_num = threads_num;
            thread_data[i].node_num = message->node_num;
            thread_data[i].socket_fd = socket_fd;
            thread_data[i].remaining = rem;
            thread_data[i].password_space = (unsigned char *) malloc(thread_data[i].password_space_size);

            memcpy(thread_data[i].password_space, message->password_space, thread_data[i].password_space_size);
            split_password_space(&message->password_space, (int *) &message->password_space_size, buckets[i]);

            if (pthread_create(&threads[i], NULL, crack_password, &thread_data[i]) != 0) {
                perror("Error creating thread");
                exit(EXIT_FAILURE);
            }
        }

        for (int i = 0; i < threads_num; i++) {
            pthread_join(threads[i], NULL);
        }

        free(thread_data);
        free(prefix_salt);
        free(message->hash);
        free(message->password_space);
        free(message);
    }

    send_disconnect(socket_fd);

    if (shutdown(socket_fd, SHUT_WR) < 0) {
        perror("Shutdown failed");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    close_socket(socket_fd);

    pthread_mutex_destroy(&lock_checkpoint_count);
    pthread_mutex_destroy(&lock_found_flag);

    free(thread_last_attempt_size);
    free(thread_last_attempt);
    free(thread_progress);

    printf("NODE EXITING");

    return EXIT_SUCCESS;
}

void parse_arguments(int argc, char *argv[], char **server_ip, char **port_str, char **threads_str) {
    static struct option long_options[] = {
        {"server", required_argument, NULL, 1},
        {"port", required_argument, NULL, 2},
        {"threads", required_argument, NULL, 3},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    int opt;

    opterr = 0;

    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (opt) {
            case 1: {
                *server_ip = optarg;
                break;
            }
            case 2: {
                *port_str = optarg;
                break;
            }
            case 3: {
                *threads_str = optarg;
                break;
            }
            case 'h': {
                usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?': {
                usage(argv[0], EXIT_FAILURE, "?");
            }
            default: {
                usage(argv[0], EXIT_FAILURE, NULL);
            }
        }
    }
}

void handle_arguments(char *program_name, char *server_ip, char *port_str, char *threads_str,
                      in_port_t *port, int *threads_num) {
    if (!server_ip) {
        usage(program_name, EXIT_FAILURE, "The server is required");
    }

    if (!port_str) {
        usage(program_name, EXIT_FAILURE, "The port is required");
    }

    if (!threads_str) {
        usage(program_name, EXIT_FAILURE, "The number of threads is required");
    }

    *port = parse_in_port_t(program_name, port_str);
    *threads_num = parse_int(program_name, threads_str);

    if (*threads_num < 1) {
        usage(program_name, EXIT_FAILURE, "The number of threads cannot be less than 1");
    }
}

in_port_t parse_in_port_t(char *program_name, char *input) {
    char *end_ptr;

    errno = 0;
    uintmax_t parsed_value = strtoumax(input, &end_ptr, BASE_TEN);

    if (errno != 0) {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "There are invalid characters in the input");
    }

    if (parsed_value > UINT16_MAX) {
        usage(program_name, EXIT_FAILURE, "The in_port_t value is out of range");
    }

    return (in_port_t) parsed_value;
}

int parse_int(char *program_name, char *input) {
    char *end_ptr;

    errno = 0;
    intmax_t parsed_value = strtoimax(input, &end_ptr, BASE_TEN);

    if (errno != 0) {
        perror("Error parsing int");
        exit(EXIT_FAILURE);
    }

    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "There are invalid characters in the input");
    }

    if (parsed_value > INT_MAX || parsed_value < INT_MIN) {
        usage(program_name, EXIT_FAILURE, "The integer value is out of range");
    }

    return (int) parsed_value;
}

void convert_address(struct sockaddr_storage *socket_addr, char *ip_address) {
    memset(socket_addr, 0, sizeof(*socket_addr));

    if (inet_pton(AF_INET, ip_address, &((struct sockaddr_in *) socket_addr)->sin_addr) == 1) {
        socket_addr->ss_family = AF_INET;
    } else if (inet_pton(AF_INET6, ip_address, &((struct sockaddr_in6 *) socket_addr)->sin6_addr) == 1) {
        socket_addr->ss_family = AF_INET6;
    } else {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", ip_address);
        exit(EXIT_FAILURE);
    }
}

int create_socket(int domain, int type, int protocol) {
    int socket_fd = socket(domain, type, protocol);

    if (socket_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return socket_fd;
}

void connect_socket(int socket_fd, struct sockaddr_storage socket_addr, in_port_t port) {
    char socket_addr_str[INET6_ADDRSTRLEN];
    socklen_t socket_addr_len;
    void *v_socket_addr;

    in_port_t net_port = htons(port);

    if (socket_addr.ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr = (struct sockaddr_in *) &socket_addr;
        socket_addr_len = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        v_socket_addr = (void *) &(((struct sockaddr_in *) &socket_addr)->sin_addr);
    } else if (socket_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *) &socket_addr;
        socket_addr_len = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        v_socket_addr = (void *) &(((struct sockaddr_in6 *) &socket_addr)->sin6_addr);
    } else {
        perror("Error in converting to IPv4 or IPv6");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (inet_ntop(socket_addr.ss_family, v_socket_addr, socket_addr_str, sizeof(socket_addr_str)) == NULL) {
        perror("Invalid address family");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Connecting to: %s:%u\n", socket_addr_str, port);

    if (connect(socket_fd, (struct sockaddr *) &socket_addr, socket_addr_len) == -1) {
        perror("Error in connecting to a socket");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Connected to: %s:%u\n", socket_addr_str, port);
}

void close_socket(int socket_fd) {
    if (close(socket_fd) == -1) {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}

void ask_for_work(int socket_fd) {
    uint8_t buffer[UINT8_MAX + 1];
    uint8_t type = 1;
    uint8_t total_size = sizeof(type);

    buffer[0] = type;

    if (write(socket_fd, &total_size, sizeof(uint8_t)) < 0) {
        perror("Error in writing message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (write(socket_fd, buffer, total_size) < 0) {
        perror("Error in writing message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }
}

int get_work(int socket_fd, struct server_message *message) {
    printf("GETTING NEW WORK\n");
    uint8_t *buffer = NULL;
    ssize_t bytes_recv = receive_message(socket_fd, &buffer);

    if (bytes_recv == -1) {
        return -1;
    }

    int offset = 0;

    message->type = buffer[offset++];

    if (message->type == 2) {
        return -1;
    }

    message->node_num = buffer[offset++];

    message->hash_size = buffer[offset++];
    message->hash = malloc(message->hash_size);

    if (message->hash == NULL) {
        perror("Error allocating hash");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    memcpy(message->hash, buffer + offset, message->hash_size);
    offset += message->hash_size;

    memcpy(&message->work_size, buffer + offset, sizeof(int));
    offset += sizeof(int);

    memcpy(&message->checkpoint, buffer + offset, sizeof(int));
    offset += sizeof(int);

    message->password_space_size = buffer[offset++];
    message->password_space = malloc(message->password_space_size);

    if (message->password_space == NULL) {
        perror("Error allocating password_space");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    memcpy(message->password_space, buffer + offset, message->password_space_size);

    return 1;
}

ssize_t receive_message(int socket_fd, uint8_t **message) {
    uint8_t length_buffer[1];
    ssize_t bytes_read = read(socket_fd, length_buffer, sizeof(length_buffer));

    printf("WAITING FOR MESSAGE\n");
    if (bytes_read <= 0) {
        printf("Client disconnected or error occurred.\n");
        return -1;
    }

    uint8_t message_length = length_buffer[0];
    uint8_t *message_buffer = (uint8_t *) malloc(message_length);

    if (message_buffer == NULL) {
        perror("Memory allocation failed");
        return -1;
    }

    ssize_t total_bytes_read = 0;

    while (total_bytes_read < message_length) {
        ssize_t remaining_bytes = message_length - total_bytes_read;
        bytes_read = read(socket_fd, message_buffer + total_bytes_read, remaining_bytes);

        if (bytes_read <= 0) {
            printf("Client disconnected or error occurred.\n");
            free(message_buffer);
            return -1;
        }

        total_bytes_read += bytes_read;
    }

    *message = message_buffer;

    return total_bytes_read;
}

char *extract_password_prefix_salt(char *program_name, char *password_hash) {
    char *result = malloc(100 * sizeof(char));
    if (result == NULL) return NULL;

    if (strncmp(password_hash, "$5$", 3) == 0 || strncmp(password_hash, "$6$", 3) == 0 || strncmp(
            password_hash, "$1$", 3) == 0) {
        int index = find_index_extract_till_nth_char(password_hash, '$', 3, result);

        if (index == -1) {
            usage(program_name, 1, NULL);
        }
    } else if (strncmp(password_hash, "$y$", 3) == 0) {
        int index = find_index_extract_till_nth_char(password_hash, '$', 4, result);

        if (index == -1) {
            usage(program_name, 1, NULL);
        }
    } else if (strncmp(password_hash, "$2y$", 4) == 0 || strncmp(password_hash, "$2a$", 4) == 0 || strncmp(
                   password_hash, "$2b$", 3) == 0) {
        const int index = find_index_extract_till_nth_char(password_hash, '$', 3, result);

        if (index == -1) {
            usage(program_name, 1, NULL);
        }

        for (int i = index + 1; i < index + 23; i++) {
            result[i] = password_hash[i];
        }
    } else {
        usage(program_name, 1, "Unsupported password hash");
    }

    return result;
}

int find_index_extract_till_nth_char(char *str, char c, int num, char *result) {
    for (int i = 0; i < strlen(str); i++) {
        result[i] = str[i];

        if (str[i] == c) {
            num--;

            if (num == 0) {
                return i;
            }
        }
    }

    return -1;
}

void split_password_space(uint8_t **password_space, int *size, int limit) {
    int count = 0;

    while (count < limit) {
        int i = *size - 1;

        while (i >= 0) {
            if ((*password_space)[i] < 255) {
                (*password_space)[i]++;
                break;
            }

            (*password_space)[i] = 0;
            i--;
        }

        if (i == -1) {
            (*size)++;
            *password_space = (uint8_t *) realloc(*password_space, *size);
            (*password_space)[*size - 1] = 0;
        }

        count++;
    }
}

void *crack_password(void *arg) {
    const struct thread_data *data = (struct thread_data *) arg;
    int password_space_size = data->password_space_size;
    unsigned char *password_space = data->password_space;

    int count = 0;

    while (count < data->split) {
        if (exit_flag) {
            pthread_exit(NULL);
        }
        pthread_mutex_lock(&lock_found_flag);
        if (found_flag) {
            pthread_mutex_unlock(&lock_found_flag);
            pthread_exit(NULL);
        }
        pthread_mutex_unlock(&lock_found_flag);

        struct crypt_data crypt_data = {0};
        char *hash = crypt_r((char *) password_space, data->prefix_salt, &crypt_data);

        print_thread_guess(data->id, password_space_size, password_space);

        if (strcmp(hash, data->password_hash) == 0) {
            pthread_mutex_lock(&lock_found_flag);

            if (!found_flag) {
                found_flag = 1;
                printf("Correct password found: %s\n", (char *) password_space);
                send_password(data->socket_fd, data->node_num, password_space_size, password_space);
                printf("Sent password!\n");
                // send_disconnect(data->socket_fd);
            }
            pthread_mutex_unlock(&lock_found_flag);
            pthread_exit(NULL);
        }

        pthread_mutex_lock(&lock_checkpoint_count);

        count++;
        checkpoint_count++;

        if (thread_last_attempt[data->id - 1] != NULL) {
            free(thread_last_attempt[data->id - 1]);
        }

        thread_last_attempt[data->id - 1] = (unsigned char *) malloc(password_space_size + 1);

        if (thread_last_attempt[data->id - 1] == NULL) {
            perror("Memory allocation failed for thread_last_attempt");
            close_socket(data->socket_fd);
            exit(EXIT_FAILURE);
        }

        memcpy(thread_last_attempt[data->id - 1], password_space, password_space_size);
        thread_last_attempt[data->id - 1][password_space_size] = '\0';
        thread_last_attempt_size[data->id - 1] = password_space_size;
        thread_progress[data->id - 1]++;

        if (checkpoint_count == data->checkpoint) {
            checkpoint_count = 0;

            print_thread_subtasks(data->threads_num);

            send_update(data->socket_fd, data->node_num, data->threads_num, data->work_size);

            memset(thread_progress, 0, sizeof(int) * data->threads_num);

            uint8_t *new_buffer = NULL;
            receive_message(data->socket_fd, &new_buffer);

            int type = new_buffer[0];
            printf("MESSAGE OF %d\n", type);
            if (type == 2) {
                found_flag = 1;
                // send_disconnect(data->socket_fd);
                pthread_mutex_unlock(&lock_checkpoint_count);
                pthread_exit(NULL);
            }
        }

        pthread_mutex_unlock(&lock_checkpoint_count);

        int i = password_space_size - 1;

        while (i >= 0) {
            if (password_space[i] < 255) {
                password_space[i]++;
                break;
            }
            password_space[i] = 0;
            i--;
        }

        if (i == -1) {
            password_space_size++;
            unsigned char *new_password_space = (unsigned char *) realloc(
                password_space, password_space_size * sizeof(unsigned char));
            if (new_password_space == NULL) {
                perror("Reallocation failed");
                close_socket(data->socket_fd);
                exit(EXIT_FAILURE);
            }
            password_space = new_password_space;
            password_space[password_space_size - 1] = 0;
        }
    }

    if (data->remaining != 0 && checkpoint_count == data->remaining) {
        checkpoint_count = 0;

        print_thread_subtasks(data->threads_num);

        send_update(data->socket_fd, data->node_num, data->threads_num, data->work_size);

        memset(thread_progress, 0, sizeof(int) * data->threads_num);

        uint8_t *new_buffer = NULL;
        receive_message(data->socket_fd, &new_buffer);

        int type = new_buffer[0];
        printf("MESSAGE OF %d\n", type);
        if (type == 2) {
            found_flag = 1;
            pthread_exit(NULL);
        }
    }

    return NULL;
}

void send_update(int socket_fd, int node_num, int threads_num, int work_size) {
    int buckets[threads_num];
    int quotient = work_size / threads_num;
    int remainder = work_size % threads_num;

    for (int i = 0; i < threads_num; i++) {
        buckets[i] = quotient;
    }

    for (int i = 0; i < remainder; i++) {
        buckets[i] += 1;
    }

    uint8_t buffer[UINT8_MAX + 1];
    int offset = 0;

    buffer[offset++] = 2;
    buffer[offset++] = node_num;
    buffer[offset++] = threads_num;

    for (int j = 0; j < threads_num; j++) {
        buffer[offset++] = j + 1;
        buffer[offset++] = sizeof(int);
        memcpy(&buffer[offset], &thread_progress[j], sizeof(int));
        offset += sizeof(int);
        buffer[offset++] = sizeof(int);
        memcpy(&buffer[offset], &buckets[j], sizeof(int));
        offset += sizeof(int);
        buffer[offset++] = thread_last_attempt_size[j];
        memcpy(&buffer[offset], thread_last_attempt[j], thread_last_attempt_size[j]);
        offset += thread_last_attempt_size[j];
    }

    if (write(socket_fd, &offset, sizeof(uint8_t)) < 0) {
        perror("Error in writing update message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (write(socket_fd, buffer, offset) < 0) {
        perror("Error in writing update message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }
}

void send_password(int socket_fd, int node_num, int password_space_size, unsigned char *password_space) {
    uint8_t buffer[UINT8_MAX + 1];
    int offset = 0;

    buffer[offset++] = 3;
    buffer[offset++] = node_num;
    buffer[offset++] = password_space_size;
    memcpy(&buffer[offset], password_space, password_space_size);
    offset += password_space_size;

    if (write(socket_fd, &offset, sizeof(uint8_t)) < 0) {
        perror("Error in writing password message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (write(socket_fd, buffer, offset) < 0) {
        perror("Error in writing password message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }
}

void send_disconnect(int socket_fd) {
    uint8_t buffer[UINT8_MAX + 1];
    uint8_t type = 5;
    uint8_t total_size = sizeof(type);
    printf("SENDING DISCONNECT MESSAGE\n");
    buffer[0] = type;

    if (write(socket_fd, &total_size, sizeof(uint8_t)) < 0) {
        perror("Error in writing message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (write(socket_fd, buffer, total_size) < 0) {
        perror("Error in writing message");
        close_socket(socket_fd);
        exit(EXIT_FAILURE);
    }
}

void print_thread_guess(int thread_id, int password_space_size, unsigned char *password_space) {
    char buffer[2048];
    int offset = 0;

    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Thread ID %d, Guess: ", thread_id);

    for (int i = 0; i < password_space_size; i++) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%d ", password_space[i]);
    }

    printf("%s\n", buffer);
}

void print_thread_subtasks(int threads_num) {
    char buffer[2048];
    int offset = 0;

    for (int i = 0; i < threads_num; i++) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                           "Thread %d has completed %d subtasks, last guess: ", i + 1, thread_progress[i]);

        int j = 0;

        while (j < thread_last_attempt_size[i]) {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%d ", thread_last_attempt[i][j]);
            j++;
        }

        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\n");
    }

    printf("%s", buffer);
}

void setup_signal_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
}

void sigint_handler(int signum) {
    exit_flag = 1;
    printf("STOPPING NODE\n");
}

void usage(char *program_name, int exit_code, char *message) {
    if (message) {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s <password_hash> <num_threads> <password_length>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);

    exit(exit_code);
}