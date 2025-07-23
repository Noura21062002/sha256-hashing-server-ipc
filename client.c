#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h> // For SHA256_DIGEST_LENGTH
#include <semaphore.h>   // For sem_t
#include <errno.h>       // For errno and EINTR

// IPC Constants
#define SERVER_MSG_QUEUE_KEY 1234
#define SHM_KEY 5678
#define MAX_FILE_SIZE (256 * 1024) // 256 KB - Reduced for SHM compatibility on some systems
#define MAX_PENDING_REQUESTS 100   // Maximum request queue size

// Message Types
#define MSG_TYPE_REQUEST 1    // Hash calculation request from client
#define MSG_TYPE_CONTROL 2    // Control message
#define MSG_TYPE_STATUS_REQ 3 // Server status request
#define MSG_TYPE_RESPONSE 4   // Server response to client

// Message Structures

// Structure for request message (client to server)
struct RequestMessage
{
    long mtype;
    pid_t client_pid;
    char filename[256];
    size_t file_size;
};

// Structure for control message (control client to server)
struct ControlMessage
{
    long mtype;
    int new_max_workers;
};

// Structure for status request message (status client to server)
struct StatusRequestMessage
{
    long mtype;
    pid_t client_pid;
};

// Structure for response message (server to client)
struct ResponseMessage
{
    long mtype;
    char content[256]; // SHA-256 hash or status string
};

// RequestQueueEntry definition (must match server's SHM struct)
typedef struct
{
    pid_t client_pid;
    char filename[256];
    size_t file_size;
} RequestQueueEntry;

// Shared Memory Structure
// This MUST exactly match the SharedMemoryData struct in the server.c file.
typedef struct
{
    int max_workers;                     // Concurrent worker limit
    volatile int current_workers;        // Number of active worker processes
    int scheduling_algo;                 // Scheduling algorithm (FCFS or SJF)
    volatile int pending_requests_count; // Number of requests in queue

    RequestQueueEntry request_queue[MAX_PENDING_REQUESTS]; // Simple array

    char file_data_buffer[MAX_FILE_SIZE];
    size_t file_data_current_size;
    pid_t file_data_client_pid;
    char file_data_filename[256];
} SharedMemoryData;


// --- Client Functions ---

// Function for the client requesting file hash calculation.
void run_hash_client(const char *filepath)
{
    printf("Client Hash: Starting for file '%s'.\n", filepath);

    // 1. Get server's message queue
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Hash: Error retrieving server message queue. Ensure the server is running.");
        exit(1);
    }
    printf("Client Hash: Server message queue obtained with ID: %d\n", server_msqid);

    // Get file size
    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        perror("Client Hash: Error opening file");
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    long file_size_long = ftell(file);
    fclose(file);

    if (file_size_long == -1) {
        perror("Client Hash: Error getting file size");
        exit(1);
    }
    size_t file_size = (size_t)file_size_long;

    if (file_size > MAX_FILE_SIZE)
    {
        fprintf(stderr, "Client Hash: Error: File '%s' is too large (%zu bytes). Limit is %d bytes.\n", filepath, file_size, MAX_FILE_SIZE);
        exit(1);
    }

    // 2. Create client's response message queue
    pid_t client_pid = getpid();
    key_t client_mq_key = client_pid;
    int client_msqid = msgget(client_mq_key, IPC_CREAT | 0666);
    if (client_msqid == -1)
    {
        perror("Client Hash: Error creating client message queue");
        exit(1);
    }
    printf("Client Hash: Client message queue created with ID: %d (key: %d)\n", client_msqid, client_mq_key);

    // Send the request to the server
    struct RequestMessage request;
    request.mtype = MSG_TYPE_REQUEST;
    request.client_pid = client_pid;
    strncpy(request.filename, filepath, sizeof(request.filename) - 1);
    request.filename[sizeof(request.filename) - 1] = '\0';
    request.file_size = file_size; // Include file size for SJF

    if (msgsnd(server_msqid, &request, sizeof(struct RequestMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Hash: Error sending request to server");
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Hash: Request sent to server. Waiting for response...\n");

    // Receive response from the server
    struct ResponseMessage response;
    ssize_t bytes_received;
    do {
        bytes_received = msgrcv(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), MSG_TYPE_RESPONSE, 0);
    } while (bytes_received == -1 && errno == EINTR);


    if (bytes_received == -1)
    {
        perror("Client Hash: Error receiving response from server");
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Hash: Response from server received.\n");
    printf("Client Hash: SHA-256 received: %s\n", response.content);

    // Cleanup client resources
    msgctl(client_msqid, IPC_RMID, NULL);
    printf("Client Hash: Cleanup completed.\n");
}

// Function for the control client to modify the worker limit.
void run_control_client(int new_limit)
{
    printf("Client Control: Sending request to set worker limit to %d.\n", new_limit);

    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Control: Error retrieving server message queue. Ensure the server is running.");
        exit(1);
    }

    struct ControlMessage control;
    control.mtype = MSG_TYPE_CONTROL;
    control.new_max_workers = new_limit;

    if (msgsnd(server_msqid, &control, sizeof(struct ControlMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Control: Error sending control message to server");
        exit(1);
    }
    printf("Client Control: Control message sent successfully.\n");
}

// Function for the status client to query the server.
void run_status_client()
{
    printf("Client Status: Requesting server status.\n");

    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Status: Error retrieving server message queue. Ensure the server is running.");
        exit(1);
    }

    pid_t client_pid = getpid();
    key_t client_mq_key = client_pid;
    int client_msqid = msgget(client_mq_key, IPC_CREAT | 0666);
    if (client_msqid == -1)
    {
        perror("Client Status: Error creating client message queue");
        exit(1);
    }

    struct StatusRequestMessage status_req;
    status_req.mtype = MSG_TYPE_STATUS_REQ;
    status_req.client_pid = client_pid;

    if (msgsnd(server_msqid, &status_req, sizeof(struct StatusRequestMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Status: Error sending status request to server");
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Status: Status request sent. Waiting for response...\n");

    struct ResponseMessage response;
    ssize_t bytes_received;
    do {
        bytes_received = msgrcv(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), MSG_TYPE_RESPONSE, 0);
    } while (bytes_received == -1 && errno == EINTR);

    if (bytes_received == -1)
    {
        perror("Client Status: Error receiving status response from server");
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Status: Response from server: %s\n", response.content);

    msgctl(client_msqid, IPC_RMID, NULL);
    printf("Client Status: Cleanup completed.\n");
}

// --- Main Client Function ---

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Hash Client: %s hash <filepath>\n", argv[0]);
        fprintf(stderr, "  Control Client: %s control <new_worker_limit>\n", argv[0]);
        fprintf(stderr, "  Status Client: %s status\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[1], "hash") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Usage: %s hash <filepath>\n", argv[0]);
            exit(1);
        }
        run_hash_client(argv[2]);
    }
    else if (strcmp(argv[1], "control") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Usage: %s control <new_worker_limit>\n", argv[0]);
            exit(1);
        }
        int new_limit = atoi(argv[2]);
        if (new_limit <= 0)
        {
            fprintf(stderr, "Error: Worker limit must be a positive number.\n");
            exit(1);
        }
        run_control_client(new_limit);
    }
    else if (strcmp(argv[1], "status") == 0)
    {
        run_status_client();
    }
    else
    {
        fprintf(stderr, "Invalid argument: '%s'\n", argv[1]);
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Hash Client: %s hash <filepath>\n", argv[0]);
        fprintf(stderr, "  Control Client: %s control <new_worker_limit>\n", argv[0]);
        fprintf(stderr, "  Status Client: %s status\n", argv[0]);
        exit(1);
    }

    return 0;
}