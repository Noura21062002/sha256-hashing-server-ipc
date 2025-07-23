#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>    // For S_IRUSR | S_IWUSR
#include <unistd.h>      // For fork, getpid, read, close
#include <fcntl.h>       // For open, O_RDONLY
#include <openssl/evp.h> // For EVP API (modern OpenSSL hashing)
#include <openssl/sha.h> // For SHA256_DIGEST_LENGTH (defines SHA-256 hash size)
#include <semaphore.h>   // For POSIX semaphores
#include <sys/wait.h>    // For waitpid
#include <signal.h>      // For signal handling (SIGCHLD)
#include <errno.h>       // For errno and EINTR

// IPC Constants
#define SERVER_MSG_QUEUE_KEY 1234
#define SHM_KEY 5678
#define MAX_FILE_SIZE (256 * 1024) // 256 KB - Reduced for SHM compatibility
#define MAX_PENDING_REQUESTS 100   // Maximum request queue size
#define MAX_WORKERS_DEFAULT 5      // Default worker limit

// Named Semaphore Names
#define SEM_WORKER_LIMIT_NAME "/worker_limit_sem"
#define SEM_QUEUE_MUTEX_NAME "/queue_mutex_sem"
#define SEM_QUEUE_FILL_NAME "/queue_fill_sem"
#define SEM_SHM_INIT_NAME "/shm_init_sem" // Semaphore for SHM initialization

// Message Types
#define MSG_TYPE_REQUEST 1    // Hash calculation request from client
#define MSG_TYPE_CONTROL 2    // Control message (e.g., change worker limit)
#define MSG_TYPE_STATUS_REQ 3 // Server status request
#define MSG_TYPE_RESPONSE 4   // Server response to client (hash or status)

// Scheduling Algorithms
#define SCHED_FCFS 0 // First-Come, First-Served
#define SCHED_SJF 1  // Shortest Job First

// Structure for request message (client to server)
struct RequestMessage
{
    long mtype;
    pid_t client_pid;
    char filename[256];
    size_t file_size; // Expected file size
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

// Structure for a single entry in the shared request queue
typedef struct
{
    pid_t client_pid;
    char filename[256];
    size_t file_size;
} RequestQueueEntry;

// Shared Memory Structure
// Contains synchronization data, configuration, and the request queue.
// Named semaphores don't use SHM but names for identification.
typedef struct
{
    int max_workers;                     // Concurrent worker limit
    volatile int current_workers;        // Number of active worker processes
    int scheduling_algo;                 // Scheduling algorithm (FCFS or SJF)
    volatile int pending_requests_count; // Number of requests in queue

    // Simple array for queue management. For SJF, elements will be sorted.
    RequestQueueEntry request_queue[MAX_PENDING_REQUESTS];

    // Buffer for file data transfer.
    // Only one file can be in SHM at a time. Workers must copy it.
    char file_data_buffer[MAX_FILE_SIZE];
    size_t file_data_current_size;
    pid_t file_data_client_pid;
    char file_data_filename[256];
} SharedMemoryData;

// Global pointer to shared memory
SharedMemoryData *shm_ptr;
int server_msqid;
int shmid;

// Global pointers to named semaphores
sem_t *worker_limit_sem_ptr;
sem_t *queue_mutex_ptr;
sem_t *queue_fill_sem_ptr;
sem_t *shm_init_sem_ptr;

// --- Utility Functions for SHA-256 ---

// Calculates SHA-256 of a buffer using EVP
void digest_buffer(const char *buffer, size_t len, unsigned char *hash)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_MD *md = NULL;
    unsigned int md_len;

    md = (EVP_MD *)EVP_MD_fetch(NULL, "SHA256", NULL);
    if (md == NULL)
    {
        fprintf(stderr, "Error: Could not fetch SHA256 algorithm.\n");
        exit(EXIT_FAILURE);
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        fprintf(stderr, "Error: Could not create EVP_MD_CTX.\n");
        EVP_MD_free(md);
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
    {
        fprintf(stderr, "Error: Could not initialize digest.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestUpdate(mdctx, buffer, len))
    {
        fprintf(stderr, "Error: Could not update digest.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &md_len))
    {
        fprintf(stderr, "Error: Could not finalize digest.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
}

// Converts bytes to hexadecimal string
void bytes_to_hex(unsigned char *bytes, int len, char *hex_string)
{
    for (int i = 0; i < len; i++)
    {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    hex_string[len * 2] = '\0'; // Add null terminator
}

// --- Queue Management Functions ---

// Adds a request to the queue (mutex already acquired)
int enqueue_request(const struct RequestMessage *request)
{
    if (shm_ptr->pending_requests_count >= MAX_PENDING_REQUESTS)
    {
        fprintf(stderr, "Server: Request queue full, discarding request from PID %d.\n", request->client_pid);
        return -1;
    }

    // Add to the end of the logical array
    shm_ptr->request_queue[shm_ptr->pending_requests_count] = (RequestQueueEntry){
        .client_pid = request->client_pid,
        .file_size = request->file_size};
    strncpy(shm_ptr->request_queue[shm_ptr->pending_requests_count].filename, request->filename, sizeof(shm_ptr->request_queue[shm_ptr->pending_requests_count].filename) - 1);
    shm_ptr->request_queue[shm_ptr->pending_requests_count].filename[sizeof(shm_ptr->request_queue[shm_ptr->pending_requests_count].filename) - 1] = '\0';

    shm_ptr->pending_requests_count++;

    // If SJF, sort the entire active portion of the queue (bubble sort for simplicity)
    // This ensures the shortest job is at index 0.
    if (shm_ptr->scheduling_algo == SCHED_SJF && shm_ptr->pending_requests_count > 1)
    {
        for (int i = 0; i < shm_ptr->pending_requests_count - 1; i++)
        {
            for (int j = 0; j < shm_ptr->pending_requests_count - i - 1; j++)
            {
                if (shm_ptr->request_queue[j].file_size > shm_ptr->request_queue[j + 1].file_size)
                {
                    // Swap
                    RequestQueueEntry temp = shm_ptr->request_queue[j];
                    shm_ptr->request_queue[j] = shm_ptr->request_queue[j + 1];
                    shm_ptr->request_queue[j + 1] = temp;
                }
            }
        }
    }
    return 0;
}

// Extracts the next request (mutex already acquired)
// For both FCFS and SJF, the next job to process is always at index 0 after enqueueing/sorting.
int dequeue_request(RequestQueueEntry *entry)
{
    if (shm_ptr->pending_requests_count == 0)
    {
        return -1; // Queue empty
    }

    *entry = shm_ptr->request_queue[0]; // Take the request from the front

    // Shift all subsequent elements one position to the left
    for (int i = 0; i < shm_ptr->pending_requests_count - 1; i++)
    {
        shm_ptr->request_queue[i] = shm_ptr->request_queue[i + 1];
    }

    shm_ptr->pending_requests_count--;
    return 0;
}

// --- Signal Handler ---

// SIGCHLD signal handler to prevent zombie processes.
void sigchld_handler(int signo)
{
    int status;
    pid_t pid;
    // Use WNOHANG to avoid blocking if no children have terminated
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        // Child terminated: decrement current_workers (with mutex for consistency).
        sem_wait(queue_mutex_ptr); // Named semaphore pointer
        shm_ptr->current_workers--;
        sem_post(queue_mutex_ptr); // Named semaphore pointer
        printf("Server: Worker process PID %d terminated. Active workers: %d.\n", pid, shm_ptr->current_workers);
    }
}

// --- Worker Process Function ---

// Function executed by each child worker process. Processes a request from the queue,
// calculates the hash, and sends the response.
void worker_process()
{
    // Each worker must attach to shared memory
    SharedMemoryData *local_shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (local_shm_ptr == (void *)-1)
    {
        perror("Worker: Error attaching to shared memory");
        exit(1);
    }

    // Each worker must open named semaphores
    sem_t *local_worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, 0);
    sem_t *local_queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, 0);
    sem_t *local_queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, 0);

    if (local_worker_limit_sem_ptr == SEM_FAILED || local_queue_mutex_ptr == SEM_FAILED || local_queue_fill_sem_ptr == SEM_FAILED)
    {
        perror("Worker: Error opening named semaphores");
        shmdt(local_shm_ptr);
        exit(1);
    }

    RequestQueueEntry current_request;
    char local_file_buffer[MAX_FILE_SIZE]; // Private buffer for the file data

    // Wait for a request in the queue
    sem_wait(local_queue_fill_sem_ptr);

    // Acquire mutex to access the queue and shared buffer
    sem_wait(local_queue_mutex_ptr);

    // Dequeue the request
    if (dequeue_request(&current_request) == -1)
    {
        fprintf(stderr, "Worker: Unexpected error: queue empty after sem_wait.\n");
        sem_post(local_queue_mutex_ptr);      // Release mutex
        shmdt(local_shm_ptr);
        sem_close(local_worker_limit_sem_ptr);
        sem_close(local_queue_mutex_ptr);
        sem_close(local_queue_fill_sem_ptr);
        exit(1); // Terminate worker
    }

    // Copy data from shared buffer to private buffer to avoid conflicts.
    // This check ensures the worker is processing the file that was *just* placed in SHM by the server.
    if (current_request.client_pid != local_shm_ptr->file_data_client_pid ||
        strcmp(current_request.filename, local_shm_ptr->file_data_filename) != 0 ||
        current_request.file_size != local_shm_ptr->file_data_current_size)
    {
        fprintf(stderr, "Worker PID %d: Warning: SHM file data does not match dequeued request. This can happen with high concurrency if the server hasn't finished copying the file. Request will be discarded.\n", getpid());

        // Send an error response to the client
        char error_hash[65];
        strcpy(error_hash, "ERROR: SHM_DATA_MISMATCH");
        key_t client_mq_key = current_request.client_pid;
        int client_msqid = msgget(client_mq_key, 0666);
        if (client_msqid == -1)
        {
            perror("Worker: Error retrieving client message queue (for error response)");
        }
        else
        {
            struct ResponseMessage response;
            response.mtype = MSG_TYPE_RESPONSE;
            strcpy(response.content, error_hash);
            if (msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
            {
                perror("Worker: Error sending error response to client");
            }
        }
        sem_post(local_queue_mutex_ptr);      // Release mutex
        sem_post(local_worker_limit_sem_ptr); // Release worker limit semaphore
        shmdt(local_shm_ptr);
        sem_close(local_worker_limit_sem_ptr);
        sem_close(local_queue_mutex_ptr);
        sem_close(local_queue_fill_sem_ptr);
        exit(1); // Terminate worker
    }

    // Copy the file data from shared memory to the worker's private buffer
    memcpy(local_file_buffer, local_shm_ptr->file_data_buffer, current_request.file_size);
    printf("Worker PID %d: Processing request for file '%s' (size: %zu bytes).\n", getpid(), current_request.filename, current_request.file_size);

    sem_post(local_queue_mutex_ptr); // Release mutex

    // Calculate SHA-256 hash
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    char hash_hex_string[65];

    if (current_request.file_size > MAX_FILE_SIZE)
    {
        // Error if file size exceeds shared memory limit (should be caught earlier by server)
        fprintf(stderr, "Worker PID %d: Error: File size (%zu bytes) exceeds shared memory limit (%d bytes).\n", getpid(), current_request.file_size, MAX_FILE_SIZE);
        strcpy(hash_hex_string, "ERROR: FILE_TOO_LARGE");
    }
    else
    {
        digest_buffer(local_file_buffer, current_request.file_size, hash_bytes);
        bytes_to_hex(hash_bytes, SHA256_DIGEST_LENGTH, hash_hex_string);
    }

    // Send response to client
    key_t client_mq_key = current_request.client_pid;
    int client_msqid = msgget(client_mq_key, 0666); // Get existing client queue
    if (client_msqid == -1)
    {
        perror("Worker: Error retrieving client message queue");
    }
    else
    {
        struct ResponseMessage response;
        response.mtype = MSG_TYPE_RESPONSE;
        strcpy(response.content, hash_hex_string);
        if (msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
        {
            perror("Worker: Error sending response to client");
        }
    }

    printf("Worker PID %d: Completed processing for '%s'. Hash: %s\n", getpid(), current_request.filename, hash_hex_string);

    shmdt(local_shm_ptr);                 // Detach shared memory
    sem_post(local_worker_limit_sem_ptr); // Release worker limit semaphore
    sem_close(local_worker_limit_sem_ptr);
    sem_close(local_queue_mutex_ptr);
    sem_close(local_queue_fill_sem_ptr);
    exit(0); // Terminate worker process
}

// --- IPC Resource Cleanup Functions ---

// Function for cleaning up IPC resources (message queue, shared memory, semaphores).
void cleanup_ipc_resources()
{
    printf("Server: Initiating IPC resource cleanup...\n");

    // Close and unlink named semaphores (ignore errors as they might not exist)
    sem_unlink(SEM_WORKER_LIMIT_NAME);
    sem_unlink(SEM_QUEUE_MUTEX_NAME);
    sem_unlink(SEM_QUEUE_FILL_NAME);
    sem_unlink(SEM_SHM_INIT_NAME);

    // Close semaphore descriptors if they were successfully opened
    if (worker_limit_sem_ptr != SEM_FAILED && worker_limit_sem_ptr != NULL)
        sem_close(worker_limit_sem_ptr);
    if (queue_mutex_ptr != SEM_FAILED && queue_mutex_ptr != NULL)
        sem_close(queue_mutex_ptr);
    if (queue_fill_sem_ptr != SEM_FAILED && queue_fill_sem_ptr != NULL)
        sem_close(queue_fill_sem_ptr);
    if (shm_init_sem_ptr != SEM_FAILED && shm_init_sem_ptr != NULL)
        sem_close(shm_init_sem_ptr);

    if (shm_ptr != (void *)-1 && shm_ptr != NULL)
    {
        shmdt(shm_ptr); // Detach shared memory
    }

    if (shmid != -1)
    {
        shmctl(shmid, IPC_RMID, NULL); // Remove shared memory
    }

    if (server_msqid != -1)
    {
        msgctl(server_msqid, IPC_RMID, NULL); // Remove server message queue
    }
    printf("Server: IPC resource cleanup completed.\n");
}

// SIGINT (Ctrl+C) signal handler for graceful shutdown.
void sigint_handler(int signo)
{
    printf("\nServer: SIGINT signal received. Terminating...\n");
    cleanup_ipc_resources();
    exit(0);
}

// --- Main Server Function ---

int main(int argc, char *argv[])
{
    // Unlink named semaphores at startup (ignore errors)
    sem_unlink(SEM_WORKER_LIMIT_NAME);
    sem_unlink(SEM_QUEUE_MUTEX_NAME);
    sem_unlink(SEM_QUEUE_FILL_NAME);
    sem_unlink(SEM_SHM_INIT_NAME);

    // Clean up message queue and SHM from previous runs (ignore errors)
    int temp_msqid = msgget(SERVER_MSG_QUEUE_KEY, 0);
    if (temp_msqid != -1)
    {
        msgctl(temp_msqid, IPC_RMID, NULL);
    }
    int temp_shmid = shmget(SHM_KEY, 0, 0); // Get ID without creating/attaching
    if (temp_shmid != -1)
    {
        shmctl(temp_shmid, IPC_RMID, NULL);
    }

    // Configure SIGINT signal handler for graceful cleanup
    signal(SIGINT, sigint_handler);
    // Configure SIGCHLD signal handler to prevent zombie processes
    signal(SIGCHLD, sigchld_handler);

    // Set default scheduling algorithm
    int initial_scheduling_algo = SCHED_FCFS;
    if (argc > 1)
    {
        if (strcmp(argv[1], "sjf") == 0)
        {
            initial_scheduling_algo = SCHED_SJF;
            printf("Server: Scheduling set to SJF (Shortest Job First).\n");
        }
        else if (strcmp(argv[1], "fcfs") == 0)
        {
            initial_scheduling_algo = SCHED_FCFS;
            printf("Server: Scheduling set to FCFS (First-Come, First-Served).\n");
        }
        else
        {
            fprintf(stderr, "Server: Warning: Unknown scheduling algorithm '%s'. Using FCFS.\n", argv[1]);
        }
    }
    else
    {
        printf("Server: No scheduling algorithm specified. Using FCFS (First-Come, First-Served).\n");
    }

    printf("Server: Starting SHA-256 server.\n");

    // 1. Create/Retrieve server message queue
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    server_msqid = msgget(server_mq_key, IPC_CREAT | 0666);
    if (server_msqid == -1)
    {
        perror("Server: Error creating server message queue");
        exit(1);
    }
    printf("Server: Server message queue created/obtained with ID: %d\n", server_msqid);

    // 2. Create/Retrieve shared memory
    key_t shm_key = SHM_KEY;
    shmid = shmget(shm_key, sizeof(SharedMemoryData), IPC_CREAT | 0666);
    if (shmid == -1)
    {
        perror("Server: Error creating shared memory");
        msgctl(server_msqid, IPC_RMID, NULL);
        exit(1);
    }
    shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (shm_ptr == (void *)-1)
    {
        perror("Server: Error attaching to shared memory");
        msgctl(server_msqid, IPC_RMID, NULL);
        shmctl(shmid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Server: Shared memory attached with ID: %d\n", shmid);

    // 3. Initialize SHM and named semaphores using a single initialization semaphore (O_CREAT safe).
    shm_init_sem_ptr = sem_open(SEM_SHM_INIT_NAME, O_CREAT, 0666, 1);
    if (shm_init_sem_ptr == SEM_FAILED)
    {
        perror("Server: Error creating/opening SHM initialization semaphore");
        cleanup_ipc_resources();
        exit(1);
    }

    sem_wait(shm_init_sem_ptr); // Acquire semaphore for initialization

    // Check if shared memory is being initialized for the first time
    int first_init = (shm_ptr->max_workers == 0);

    if (first_init)
    {
        printf("Server: Initializing shared memory and opening named semaphores.\n");
        // Open/create named semaphores. They will always be newly created here.
        worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, O_CREAT, 0666, MAX_WORKERS_DEFAULT);
        queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, O_CREAT, 0666, 1);
        queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, O_CREAT, 0666, 0);

        if (worker_limit_sem_ptr == SEM_FAILED || queue_mutex_ptr == SEM_FAILED || queue_fill_sem_ptr == SEM_FAILED)
        {
            perror("Server: Error opening/creating named semaphores");
            sem_post(shm_init_sem_ptr); // Release initialization semaphore
            cleanup_ipc_resources();
            exit(1);
        }

        shm_ptr->max_workers = MAX_WORKERS_DEFAULT;
        shm_ptr->current_workers = 0;
        shm_ptr->scheduling_algo = initial_scheduling_algo;
        shm_ptr->pending_requests_count = 0;
        // No queue_head/tail needed for the simplified array queue
        shm_ptr->file_data_current_size = 0;
        shm_ptr->file_data_client_pid = 0;
        memset(shm_ptr->file_data_filename, 0, sizeof(shm_ptr->file_data_filename));
    }
    else
    {
        printf("Server: Shared memory already initialized. Opening existing semaphores.\n");
        // If SHM exists, open existing semaphores without O_CREAT (initial cleanup prevents conflicts).
        worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, 0); // 0 for not creating
        queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, 0);
        queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, 0);

        if (worker_limit_sem_ptr == SEM_FAILED || queue_mutex_ptr == SEM_FAILED || queue_fill_sem_ptr == SEM_FAILED)
        {
            perror("Server: Error opening existing named semaphores");
            sem_post(shm_init_sem_ptr); // Release initialization semaphore
            cleanup_ipc_resources();
            exit(1);
        }
    }
    sem_post(shm_init_sem_ptr); // Release initialization semaphore
    // We don't close shm_init_sem_ptr here, it will be closed and unlinked in cleanup_ipc_resources.

    printf("Server: Waiting for requests (Worker limit: %d)...\n", shm_ptr->max_workers);

    // Buffer to receive messages of different types
    union
    {
        long mtype;
        struct RequestMessage req;
        struct ControlMessage ctrl;
        struct StatusRequestMessage status_req;
    } msg_buffer;

    while (1)
    {
        ssize_t bytes_received;
        // Receive any type of message, handle EINTR
        do
        {
            bytes_received = msgrcv(server_msqid, &msg_buffer, sizeof(msg_buffer) - sizeof(long), 0, 0);
        } while (bytes_received == -1 && errno == EINTR);

        if (bytes_received == -1)
        {
            perror("Server: Critical error receiving message");
            // For a critical error (not EINTR), you might want to exit or log more severely
            continue;
        }

        switch (msg_buffer.mtype)
        {
        case MSG_TYPE_REQUEST:
        {
            struct RequestMessage *request = &msg_buffer.req;
            printf("Server: Received request from PID %d for file '%s' (size: %zu bytes).\n",
                   request->client_pid, request->filename, request->file_size);

            // Acquire mutex to protect access to SHM buffer and queue
            sem_wait(queue_mutex_ptr);

            // --- IMPORTANT FIX: Read file data into SHM buffer ---
            int fd = open(request->filename, O_RDONLY);
            if (fd == -1)
            {
                perror("Server: Error opening file for processing");
                sem_post(queue_mutex_ptr); // Release mutex
                // Send error response to client
                key_t client_mq_key = request->client_pid;
                int client_msqid_resp = msgget(client_mq_key, 0666);
                if (client_msqid_resp != -1)
                {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    strcpy(response.content, "ERROR: FILE_NOT_FOUND_OR_ACCESSIBLE");
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
                continue; // Skip to next message
            }

            // Check if file size exceeds MAX_FILE_SIZE
            if (request->file_size > MAX_FILE_SIZE)
            {
                fprintf(stderr, "Server: Error: File '%s' (size %zu bytes) exceeds MAX_FILE_SIZE (%d bytes). Request discarded.\n", request->filename, request->file_size, MAX_FILE_SIZE);
                close(fd);
                sem_post(queue_mutex_ptr); // Release mutex
                // Send error response to client
                key_t client_mq_key = request->client_pid;
                int client_msqid_resp = msgget(client_mq_key, 0666);
                if (client_msqid_resp != -1)
                {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    strcpy(response.content, "ERROR: FILE_TOO_LARGE");
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
                continue; // Skip to next message
            }

            ssize_t bytes_read = read(fd, shm_ptr->file_data_buffer, request->file_size);
            close(fd);

            if (bytes_read == -1 || (size_t)bytes_read != request->file_size)
            {
                perror("Server: Error reading file into shared memory buffer");
                sem_post(queue_mutex_ptr); // Release mutex
                // Send error response to client
                key_t client_mq_key = request->client_pid;
                int client_msqid_resp = msgget(client_mq_key, 0666);
                if (client_msqid_resp != -1)
                {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    strcpy(response.content, "ERROR: FILE_READ_FAILED");
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
                continue; // Skip to next message
            }

            // Update SHM metadata for the file
            shm_ptr->file_data_current_size = (size_t)bytes_read;
            shm_ptr->file_data_client_pid = request->client_pid;
            strncpy(shm_ptr->file_data_filename, request->filename, sizeof(shm_ptr->file_data_filename) - 1);
            shm_ptr->file_data_filename[sizeof(shm_ptr->file_data_filename) - 1] = '\0';

            // Add the request to the queue
            if (enqueue_request(request) == 0)
            {
                printf("Server: Request from PID %d enqueued. Pending requests: %d.\n", request->client_pid, shm_ptr->pending_requests_count);
                sem_post(queue_mutex_ptr);    // Release mutex
                sem_post(queue_fill_sem_ptr); // Signal that a request is in the queue

                // Try to acquire the worker limit semaphore
                // This will block if the maximum worker limit has been reached
                sem_wait(worker_limit_sem_ptr);

                // Semaphore acquired, we can create a new worker
                sem_wait(queue_mutex_ptr); // Protect current_workers
                shm_ptr->current_workers++;
                printf("Server: Creating new worker. Active workers: %d.\n", shm_ptr->current_workers);
                sem_post(queue_mutex_ptr);

                pid_t pid = fork();
                if (pid == -1)
                {
                    perror("Server: Error forking worker process");
                    sem_wait(queue_mutex_ptr); // Protect current_workers
                    shm_ptr->current_workers--;
                    sem_post(queue_mutex_ptr);
                    sem_post(worker_limit_sem_ptr); // Release semaphore if fork fails
                }
                else if (pid == 0)
                {
                    // Child process code (worker)
                    worker_process();
                    // Worker terminates with exit(0) or exit(1)
                }
                else
                {
                    // Parent process code (main server)
                    // Continue main loop to receive new requests
                }
            }
            else
            {
                sem_post(queue_mutex_ptr); // Release mutex if queue is full
                // Send an error message to the client if the queue is full
                key_t client_mq_key = request->client_pid;
                int client_msqid_resp = msgget(client_mq_key, 0666);
                if (client_msqid_resp != -1)
                {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    strcpy(response.content, "ERROR: SERVER_QUEUE_FULL");
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
            }
            break;
        }
        case MSG_TYPE_CONTROL:
        {
            struct ControlMessage *control = &msg_buffer.ctrl;
            sem_wait(queue_mutex_ptr); // Protect access to max_workers
            int old_max_workers = shm_ptr->max_workers;
            shm_ptr->max_workers = control->new_max_workers;
            printf("Server: Max worker limit updated from %d to %d.\n", old_max_workers, shm_ptr->max_workers);

            // If the new limit is greater, post to the semaphore to allow more workers
            for (int i = 0; i < shm_ptr->max_workers - old_max_workers; i++)
            {
                sem_post(worker_limit_sem_ptr);
            }
            sem_post(queue_mutex_ptr);
            break;
        }
        case MSG_TYPE_STATUS_REQ:
        {
            struct StatusRequestMessage *status_req = &msg_buffer.status_req;
            sem_wait(queue_mutex_ptr); // Protect access to counters
            int pending = shm_ptr->pending_requests_count;
            int active = shm_ptr->current_workers;
            int max_w = shm_ptr->max_workers;
            char *sched_algo_name = (shm_ptr->scheduling_algo == SCHED_FCFS) ? "FCFS" : "SJF";
            sem_post(queue_mutex_ptr);

            key_t client_mq_key = status_req->client_pid;
            int client_msqid_resp = msgget(client_mq_key, 0666);
            if (client_msqid_resp == -1)
            {
                perror("Server: Error retrieving client message queue for status");
            }
            else
            {
                struct ResponseMessage response;
                response.mtype = MSG_TYPE_RESPONSE;
                snprintf(response.content, sizeof(response.content),
                         "Status: Pending=%d, Active=%d/%d, Sched=%s",
                         pending, active, max_w, sched_algo_name);
                if (msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
                {
                    perror("Server: Error sending status response to client");
                }
            }
            printf("Server: Sent status to PID %d.\n", status_req->client_pid);
            break;
        }
        default:
            fprintf(stderr, "Server: Unknown message type received: %ld\n", msg_buffer.mtype);
            break;
        }
    }

    // Cleanup happens via SIGINT handler.
    cleanup_ipc_resources();
    return 0;
}