#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h> // Per SHA256_DIGEST_LENGTH
#include <semaphore.h>   // NECESSARIO per sem_t

// --- Costanti per IPC ---
#define SERVER_MSG_QUEUE_KEY 1234
#define SHM_KEY 5678
#define MAX_FILE_SIZE (256 * 1024) // 256 KB - Ridotto per compatibilità con limiti di SHM su alcuni sistemi
#define MAX_PENDING_REQUESTS 100   // Dimensione massima della coda di richieste (per coerenza con server)

// --- Tipi di Messaggio ---
#define MSG_TYPE_REQUEST 1    // Richiesta di calcolo hash dal client
#define MSG_TYPE_CONTROL 2    // Messaggio di controllo (es. cambio limite worker)
#define MSG_TYPE_STATUS_REQ 3 // Richiesta di stato del server
#define MSG_TYPE_RESPONSE 4   // Risposta del server al client (hash o stato)

// --- Strutture dei Messaggi ---

// Struttura del messaggio di richiesta (dal client al server)
struct RequestMessage
{
    long mtype;         // Tipo di messaggio (MSG_TYPE_REQUEST)
    pid_t client_pid;   // PID del client per la sua coda di risposta
    char filename[256]; // Nome originale del file
    size_t file_size;   // Dimensione del file (per schedulazione SJF)
};

// Struttura del messaggio di controllo (da client di controllo al server)
struct ControlMessage
{
    long mtype;          // Tipo di messaggio (MSG_TYPE_CONTROL)
    int new_max_workers; // Nuovo limite massimo di worker
};

// Struttura del messaggio di richiesta di stato (da client di stato al server)
struct StatusRequestMessage
{
    long mtype;       // Tipo di messaggio (MSG_TYPE_STATUS_REQ)
    pid_t client_pid; // PID del client per la sua coda di risposta
};

// Struttura del messaggio di risposta (dal server al client)
struct ResponseMessage
{
    long mtype;        // Tipo di messaggio (MSG_TYPE_RESPONSE)
    char content[256]; // Contenuto: hash SHA-256 o stringa di stato
};

// Definizione completa di RequestQueueEntry per coerenza con la SHM del server
typedef struct
{
    pid_t client_pid;
    char filename[256];
    size_t file_size;
} RequestQueueEntry;

// --- Struttura della Memoria Condivisa (definizione completa per coerenza) ---
// Questa deve essere identica a quella nel server per garantire che shm_ptr punti correttamente
// ai dati e che sizeof(SharedMemoryData) sia lo stesso.
// I semafori nominati non sono parte della SHM, quindi non sono qui.
typedef struct
{
    // I semafori nominati NON sono inclusi in questa struttura,
    // poiché sono gestiti tramite nomi e non risiedono nella SHM.
    // I campi seguenti sono quelli che effettivamente risiedono nella SHM.
    int max_workers;                     // Limite configurabile di worker concorrenti
    volatile int current_workers;        // Numero di processi worker attivi (volatile per accesso concorrente)
    int scheduling_algo;                 // Algoritmo di schedulazione (FCFS o SJF)
    volatile int pending_requests_count; // Numero di richieste in coda (volatile)

    RequestQueueEntry request_queue[MAX_PENDING_REQUESTS];
    int queue_head; // Indice del primo elemento nella coda
    int queue_tail; // Indice del prossimo slot disponibile

    char file_data_buffer[MAX_FILE_SIZE];
    size_t file_data_current_size;
    pid_t file_data_client_pid;
    char file_data_filename[256];
} SharedMemoryData;

// --- Funzioni Client ---

/**
 * @brief Funzione per il client "normale" che richiede il calcolo dell'hash di un file.
 * @param filepath Percorso del file da processare.
 */
void run_hash_client(const char *filepath)
{
    printf("Client Hash: Avvio per il file '%s'.\n", filepath);

    // 1. Recupero della coda di messaggi del server
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Hash: Errore nel recupero della coda di messaggi del server. Assicurati che il server sia in esecuzione.");
        exit(1);
    }
    printf("Client Hash: Coda di messaggi del server ottenuta con ID: %d\n", server_msqid);

    // 2. Recupero della memoria condivisa
    key_t shm_key = SHM_KEY;
    int shmid = shmget(shm_key, sizeof(SharedMemoryData), 0666);
    if (shmid == -1)
    {
        perror("Client Hash: Errore nel recupero della memoria condivisa. Assicurati che il server sia in esecuzione.");
        exit(1);
    }
    SharedMemoryData *shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (shm_ptr == (void *)-1)
    {
        perror("Client Hash: Errore nell'attaccamento alla memoria condivisa");
        exit(1);
    }
    printf("Client Hash: Memoria condivisa attaccata con ID: %d\n", shmid);

    // 3. Creazione della coda di messaggi di risposta del client
    pid_t client_pid = getpid();
    key_t client_mq_key = client_pid;
    int client_msqid = msgget(client_mq_key, IPC_CREAT | 0666);
    if (client_msqid == -1)
    {
        perror("Client Hash: Errore nella creazione della coda di messaggi del client");
        shmdt(shm_ptr);
        exit(1);
    }
    printf("Client Hash: Coda di messaggi del client creata con ID: %d (chiave: %d)\n", client_msqid, client_mq_key);

    // Leggi il contenuto del file e scrivilo nella memoria condivisa
    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        perror("Client Hash: Errore nell'apertura del file");
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size > MAX_FILE_SIZE)
    {
        fprintf(stderr, "Client Hash: Errore: Il file '%s' è troppo grande (%ld bytes). Il limite è %d bytes.\n", filepath, file_size, MAX_FILE_SIZE);
        fclose(file);
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }

    // Scrivi il file nel buffer della memoria condivisa
    // NOTA: Questa scrittura non è protetta da mutex qui,
    // si assume che il server preleverà i dati subito dopo aver ricevuto la richiesta.
    // Per un sistema più robusto, il client dovrebbe acquisire un mutex prima di scrivere.
    size_t bytes_read = fread(shm_ptr->file_data_buffer, 1, file_size, file);
    if (bytes_read != file_size)
    {
        fprintf(stderr, "Client Hash: Errore nella lettura del file. Letti %zu bytes su %ld.\n", bytes_read, file_size);
        fclose(file);
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    // Aggiorna i metadati del file nel buffer condiviso
    shm_ptr->file_data_current_size = bytes_read;
    shm_ptr->file_data_client_pid = client_pid;
    strncpy(shm_ptr->file_data_filename, filepath, sizeof(shm_ptr->file_data_filename) - 1);
    shm_ptr->file_data_filename[sizeof(shm_ptr->file_data_filename) - 1] = '\0';

    fclose(file);
    printf("Client Hash: File '%s' letto e scritto in memoria condivisa (%zu bytes).\n", filepath, shm_ptr->file_data_current_size);

    // Invia la richiesta al server
    struct RequestMessage request;
    request.mtype = MSG_TYPE_REQUEST;
    request.client_pid = client_pid;
    strncpy(request.filename, filepath, sizeof(request.filename) - 1);
    request.filename[sizeof(request.filename) - 1] = '\0';
    request.file_size = file_size; // Includi la dimensione del file per SJF

    if (msgsnd(server_msqid, &request, sizeof(struct RequestMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Hash: Errore nell'invio della richiesta al server");
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Hash: Richiesta inviata al server. In attesa di risposta...\n");

    // Ricevi la risposta dal server
    struct ResponseMessage response;
    if (msgrcv(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), MSG_TYPE_RESPONSE, 0) == -1)
    {
        perror("Client Hash: Errore nella ricezione della risposta dal server");
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Hash: Risposta dal server ricevuta.\n");
    printf("Client Hash: SHA-256 ricevuto: %s\n", response.content);

    // Pulizia delle risorse del client
    shmdt(shm_ptr);
    msgctl(client_msqid, IPC_RMID, NULL); // Rimuovi la coda di messaggi di risposta del client
    printf("Client Hash: Pulizia completata.\n");
}

/**
 * @brief Funzione per il client di controllo per modificare il limite di worker.
 * @param new_limit Il nuovo limite massimo di worker.
 */
void run_control_client(int new_limit)
{
    printf("Client Control: Invio richiesta per impostare limite worker a %d.\n", new_limit);

    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Control: Errore nel recupero della coda di messaggi del server. Assicurati che il server sia in esecuzione.");
        exit(1);
    }

    struct ControlMessage control;
    control.mtype = MSG_TYPE_CONTROL;
    control.new_max_workers = new_limit;

    if (msgsnd(server_msqid, &control, sizeof(struct ControlMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Control: Errore nell'invio del messaggio di controllo al server");
        exit(1);
    }
    printf("Client Control: Messaggio di controllo inviato con successo.\n");
}

/**
 * @brief Funzione per il client di stato per interrogare il server.
 */
void run_status_client()
{
    printf("Client Status: Richiesta stato del server.\n");

    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Status: Errore nel recupero della coda di messaggi del server. Assicurati che il server sia in esecuzione.");
        exit(1);
    }

    pid_t client_pid = getpid();
    key_t client_mq_key = client_pid;
    int client_msqid = msgget(client_mq_key, IPC_CREAT | 0666);
    if (client_msqid == -1)
    {
        perror("Client Status: Errore nella creazione della coda di messaggi del client");
        exit(1);
    }

    struct StatusRequestMessage status_req;
    status_req.mtype = MSG_TYPE_STATUS_REQ;
    status_req.client_pid = client_pid;

    if (msgsnd(server_msqid, &status_req, sizeof(struct StatusRequestMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Status: Errore nell'invio della richiesta di stato al server");
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Status: Richiesta di stato inviata. In attesa di risposta...\n");

    struct ResponseMessage response;
    if (msgrcv(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), MSG_TYPE_RESPONSE, 0) == -1)
    {
        perror("Client Status: Errore nella ricezione della risposta di stato dal server");
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client Status: Risposta dal server: %s\n", response.content);

    msgctl(client_msqid, IPC_RMID, NULL);
    printf("Client Status: Pulizia completata.\n");
}

// --- Funzione Main del Client ---

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Utilizzo:\n");
        fprintf(stderr, "  Client Hash: %s hash <percorso_file>\n", argv[0]);
        fprintf(stderr, "  Client Controllo: %s control <nuovo_limite_worker>\n", argv[0]);
        fprintf(stderr, "  Client Stato: %s status\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[1], "hash") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Utilizzo: %s hash <percorso_file>\n", argv[0]);
            exit(1);
        }
        run_hash_client(argv[2]);
    }
    else if (strcmp(argv[1], "control") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Utilizzo: %s control <nuovo_limite_worker>\n", argv[0]);
            exit(1);
        }
        int new_limit = atoi(argv[2]);
        if (new_limit <= 0)
        {
            fprintf(stderr, "Errore: Il limite di worker deve essere un numero positivo.\n");
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
        fprintf(stderr, "Argomento non valido: '%s'\n", argv[1]);
        fprintf(stderr, "Utilizzo:\n");
        fprintf(stderr, "  Client Hash: %s hash <percorso_file>\n", argv[0]);
        fprintf(stderr, "  Client Controllo: %s control <nuovo_limite_worker>\n", argv[0]);
        fprintf(stderr, "  Client Stato: %s status\n", argv[0]);
        exit(1);
    }

    return 0;
}
