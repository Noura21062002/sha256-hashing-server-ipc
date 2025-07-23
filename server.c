#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>    // Per S_IRUSR | S_IWUSR, stat
#include <unistd.h>      // Per fork, getpid, read, close
#include <fcntl.h>       // Per open, O_RDONLY, O_CREAT
#include <openssl/sha.h> // Per SHA256_DIGEST_LENGTH (ancora utile per la dimensione)
#include <openssl/evp.h> // Per le nuove API EVP
#include <semaphore.h>   // Per semafori POSIX
#include <sys/wait.h>    // Per waitpid
#include <signal.h>      // Per gestione segnali (SIGCHLD, SIGINT)
#include <errno.h>       // Per errno e EINTR

// Costanti IPC
#define SERVER_MSG_QUEUE_KEY 1234
#define SHM_KEY 5678
#define MAX_FILE_SIZE (256 * 1024) // 256 KB - Limite per i file da processare
#define MAX_PENDING_REQUESTS 100   // Dimensione massima coda richieste
#define MAX_WORKERS_DEFAULT 5      // Limite worker predefinito

// Nomi Semafori Nominati
#define SEM_WORKER_LIMIT_NAME "/server_worker_limit_sem"
#define SEM_QUEUE_MUTEX_NAME "/server_queue_mutex_sem"
#define SEM_QUEUE_FILL_NAME "/server_queue_fill_sem"

// Tipi di Messaggio
#define MSG_TYPE_REQUEST 1    // Richiesta calcolo hash dal client
#define MSG_TYPE_CONTROL 2    // Messaggio di controllo (es. cambia limite worker)
#define MSG_TYPE_STATUS_REQ 3 // Richiesta stato server
#define MSG_TYPE_RESPONSE 4   // Risposta server al client (hash o stato)

// Algoritmi di Scheduling
#define SCHED_FCFS 0 // First-Come, First-Served
#define SCHED_SJF 1  // Shortest Job First

// Struttura per messaggio di richiesta (client a server)
struct RequestMessage
{
    long mtype;
    pid_t client_pid;
    char filename[256];
    size_t file_size; // Dimensione attesa del file
};

// Struttura per messaggio di controllo (client di controllo a server)
struct ControlMessage
{
    long mtype;
    int new_max_workers;
};

// Struttura per messaggio di richiesta stato (client di stato a server)
struct StatusRequestMessage
{
    long mtype;
    pid_t client_pid;
};

// Struttura per messaggio di risposta (server a client)
struct ResponseMessage
{
    long mtype;
    char content[256]; // Hash SHA-256 o stringa di stato
};

// Struttura per una singola voce nella coda di richieste condivisa
typedef struct
{
    pid_t client_pid;
    char filename[256];
    size_t file_size;
} RequestQueueEntry;

// Struttura della Memoria Condivisa
// Contiene dati di sincronizzazione, configurazione e la coda di richieste.
// I semafori nominati non usano SHM ma nomi per l'identificazione.
typedef struct
{
    int max_workers;                // Limite worker concorrenti
    volatile int current_workers;   // Numero di processi worker attivi
    int scheduling_algo;            // Algoritmo di scheduling (FCFS o SJF)
    volatile int pending_requests_count; // Numero di richieste in coda (head sempre a 0, si spostano gli elementi)

    // Semplice array per la gestione della coda. Per SJF, gli elementi saranno ordinati.
    RequestQueueEntry request_queue[MAX_PENDING_REQUESTS];

} SharedMemoryData;

// Puntatore globale alla memoria condivisa
SharedMemoryData *shm_ptr = NULL; // Inizializza a NULL
int server_msqid = -1;
int shmid = -1;

// Puntatori globali ai semafori nominati
sem_t *worker_limit_sem_ptr = SEM_FAILED;
sem_t *queue_mutex_ptr = SEM_FAILED;
sem_t *queue_fill_sem_ptr = SEM_FAILED;

// Flag per indicare al ciclo principale di terminare
volatile sig_atomic_t server_should_exit = 0;


// Funzioni di Utilità per SHA-256 (usando le API EVP)

// Calcola SHA-256 di un buffer usando le API EVP (OpenSSL 3.0+)
void digest_buffer(const char *buffer, size_t len, unsigned char *hash)
{
    EVP_MD_CTX *mdctx = NULL; // Contesto per l'operazione di digest
    const EVP_MD *md = NULL;  // Algoritmo di digest (SHA256)
    unsigned int md_len;      // Lunghezza del digest
    int ret = 0; // Return value for OpenSSL functions

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Errore: Impossibile creare il contesto EVP_MD_CTX.\n");
        goto err;
    }

    md = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (md == NULL) {
        fprintf(stderr, "Errore: Impossibile recuperare l'algoritmo SHA256.\n");
        goto err;
    }

    ret = EVP_DigestInit_ex(mdctx, md, NULL);
    if (ret != 1) {
        fprintf(stderr, "Errore: Impossibile inizializzare il digest EVP (EVP_DigestInit_ex).\n");
        goto err;
    }

    ret = EVP_DigestUpdate(mdctx, buffer, len);
    if (ret != 1) {
        fprintf(stderr, "Errore: Impossibile aggiornare il digest EVP (EVP_DigestUpdate).\n");
        goto err;
    }

    ret = EVP_DigestFinal_ex(mdctx, hash, &md_len);
    if (ret != 1) {
        fprintf(stderr, "Errore: Impossibile finalizzare il digest EVP (EVP_DigestFinal_ex).\n");
        goto err;
    }

    if (md_len != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "Errore: Lunghezza hash SHA256 non corrispondente (%u vs %d).\n", md_len, SHA256_DIGEST_LENGTH);
        goto err;
    }

err:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (md) EVP_MD_free((EVP_MD *)md);
    // If an error occurred and we reached here, ensure proper termination.
    // In a real application, you might want to return an error code or set an error flag.
    // For this example, we'll let it proceed, but the hash might be garbage if an error occurred.
    // A more robust error handling would prevent the worker from sending a bad hash.
}

// Converte byte in stringa esadecimale
void bytes_to_hex(unsigned char *bytes, int len, char *hex_string)
{
    for (int i = 0; i < len; i++)
    {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    hex_string[len * 2] = '\0'; // Aggiungi terminatore nullo
}

// Funzioni di Gestione Coda

// Aggiunge una richiesta alla coda (mutex già acquisito)
// La coda è gestita come un array, sempre con il primo elemento come "head" logica.
// Per SJF, gli elementi vengono riordinati dopo ogni aggiunta.
int enqueue_request(const struct RequestMessage *request)
{
    if (shm_ptr->pending_requests_count >= MAX_PENDING_REQUESTS)
    {
        fprintf(stderr, "Server: Coda richieste piena, scarto richiesta da PID %d.\n", request->client_pid);
        return -1;
    }

    // Aggiungi alla fine logica dell'array
    shm_ptr->request_queue[shm_ptr->pending_requests_count].client_pid = request->client_pid;
    strncpy(shm_ptr->request_queue[shm_ptr->pending_requests_count].filename, request->filename, sizeof(shm_ptr->request_queue[shm_ptr->pending_requests_count].filename) - 1);
    shm_ptr->request_queue[shm_ptr->pending_requests_count].filename[sizeof(shm_ptr->request_queue[shm_ptr->pending_requests_count].filename) - 1] = '\0';
    shm_ptr->request_queue[shm_ptr->pending_requests_count].file_size = request->file_size;

    shm_ptr->pending_requests_count++;

    // Se SJF, ordina l'intera porzione attiva della coda
    if (shm_ptr->scheduling_algo == SCHED_SJF && shm_ptr->pending_requests_count > 1)
    {
        // Bubble sort per semplicità, ma per un numero elevato di richieste
        // sarebbe meglio una struttura dati con priorità o un qsort su un array temporaneo.
        for (int i = 0; i < shm_ptr->pending_requests_count - 1; i++)
        {
            for (int j = 0; j < shm_ptr->pending_requests_count - i - 1; j++)
            {
                if (shm_ptr->request_queue[j].file_size > shm_ptr->request_queue[j + 1].file_size)
                {
                    // Scambia gli elementi
                    RequestQueueEntry temp = shm_ptr->request_queue[j];
                    shm_ptr->request_queue[j] = shm_ptr->request_queue[j + 1];
                    shm_ptr->request_queue[j + 1] = temp;
                }
            }
        }
        printf("Server: Coda riordinata per SJF. Prossimo file: '%s' (dim: %zu)\n",
               shm_ptr->request_queue[0].filename, shm_ptr->request_queue[0].file_size);
    }
    return 0;
}

// Estrae la prossima richiesta (mutex già acquisito)
// La prossima richiesta è sempre la prima nell'array (indice 0).
int dequeue_request(RequestQueueEntry *entry)
{
    if (shm_ptr->pending_requests_count == 0)
    {
        return -1; // Coda vuota
    }

    *entry = shm_ptr->request_queue[0]; // Prendi la richiesta dalla parte anteriore

    // Sposta tutti gli elementi successivi di una posizione a sinistra per "rimuovere" il primo
    for (int i = 0; i < shm_ptr->pending_requests_count - 1; i++)
    {
        shm_ptr->request_queue[i] = shm_ptr->request_queue[i + 1];
    }

    shm_ptr->pending_requests_count--;
    return 0;
}

// Funzioni di Pulizia Risorse IPC

// Funzione per la pulizia delle risorse IPC (coda messaggi, memoria condivisa, semafori).
void cleanup_ipc_resources()
{
    printf("Server: Avvio pulizia risorse IPC...\n");

    // Chiudi e scollega i semafori nominati
    if (worker_limit_sem_ptr != SEM_FAILED && worker_limit_sem_ptr != NULL) {
        sem_close(worker_limit_sem_ptr);
        sem_unlink(SEM_WORKER_LIMIT_NAME);
        printf("Server: Semaforo '%s' chiuso e scollegato.\n", SEM_WORKER_LIMIT_NAME);
    }
    if (queue_mutex_ptr != SEM_FAILED && queue_mutex_ptr != NULL) {
        sem_close(queue_mutex_ptr);
        sem_unlink(SEM_QUEUE_MUTEX_NAME);
        printf("Server: Semaforo '%s' chiuso e scollegato.\n", SEM_QUEUE_MUTEX_NAME);
    }
    if (queue_fill_sem_ptr != SEM_FAILED && queue_fill_sem_ptr != NULL) {
        sem_close(queue_fill_sem_ptr);
        sem_unlink(SEM_QUEUE_FILL_NAME);
        printf("Server: Semaforo '%s' chiuso e scollegato.\n", SEM_QUEUE_FILL_NAME);
    }

    if (shm_ptr != (void *)-1 && shm_ptr != NULL)
    {
        if (shmdt(shm_ptr) == -1) {
            perror("Server: Errore nel distacco della memoria condivisa");
        }
        printf("Server: Memoria condivisa distaccata.\n");
    }

    if (shmid != -1)
    {
        if (shmctl(shmid, IPC_RMID, NULL) == -1) {
            perror("Server: Errore nella rimozione della memoria condivisa");
        }
        printf("Server: Memoria condivisa rimossa con ID: %d.\n", shmid);
    }

    if (server_msqid != -1)
    {
        if (msgctl(server_msqid, IPC_RMID, NULL) == -1) {
            perror("Server: Errore nella rimozione della coda messaggi del server");
        }
        printf("Server: Coda messaggi server rimossa con ID: %d.\n", server_msqid);
    }
    printf("Server: Pulizia risorse IPC completata.\n");
}

// Gestore Segnali

// Gestore del segnale SIGCHLD per prevenire processi zombie.
void sigchld_handler(int signo)
{
    int status;
    pid_t pid;
    // Usa WNOHANG per evitare di bloccare se nessun figlio è terminato
    // Loop per raccogliere tutti i figli terminati (potrebbero esserne terminati più di uno)
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        // Figlio terminato: decrementa current_workers (con mutex per coerenza).
        // È cruciale che questo semaforo sia accessibile globalmente dal gestore.
        if (queue_mutex_ptr != SEM_FAILED && queue_mutex_ptr != NULL) { // Verifica che sia stato inizializzato
            sem_wait(queue_mutex_ptr);
            if (shm_ptr != NULL && shm_ptr != (void*)-1) { // Verifica che shm_ptr sia valido
                shm_ptr->current_workers--;
                printf("Server: Processo worker PID %d terminato. Worker attivi: %d.\n", pid, shm_ptr->current_workers);
            }
            sem_post(queue_mutex_ptr);
        } else {
            // Se i semafori non sono ancora inizializzati o sono già stati chiusi
            fprintf(stderr, "Server: Avviso: SIGCHLD ricevuto ma semafori non disponibili per aggiornare worker_count.\n");
        }
    }
}

// Gestore del segnale SIGINT (Ctrl+C) per uno spegnimento grazioso.
void sigint_handler(int signo)
{
    printf("\nServer: Segnale SIGINT ricevuto. Avvio terminazione graziosa...\n");
    server_should_exit = 1; // Imposta il flag per il ciclo principale
    // Posta sui semafori per sbloccare eventuali `msgrcv` bloccati
    // e permettere ai worker in attesa di richieste di terminare.
    // Invia un messaggio fittizio per sbloccare msgrcv se non ci sono richieste.
    // Se msgrcv è bloccato, l'IPC_RMID lo sbloccherà con errno = EIDRM.
}

// Funzione Processo Worker

// Funzione eseguita da ogni processo worker figlio. Elabora una richiesta dalla coda,
// calcola l'hash e invia la risposta.
void worker_process()
{
    // Ogni worker deve attaccarsi alla memoria condivisa
    SharedMemoryData *local_shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (local_shm_ptr == (void *)-1)
    {
        perror("Worker: Errore nell'attaccarsi alla memoria condivisa");
        exit(1);
    }

    // Ogni worker deve aprire i semafori nominati (NON O_CREAT)
    sem_t *local_worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, 0);
    sem_t *local_queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, 0);
    sem_t *local_queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, 0);

    if (local_worker_limit_sem_ptr == SEM_FAILED || local_queue_mutex_ptr == SEM_FAILED ||
        local_queue_fill_sem_ptr == SEM_FAILED)
    {
        perror("Worker: Errore nell'aprire i semafori nominati");
        shmdt(local_shm_ptr);
        exit(1); // Il worker non può operare senza semafori
    }

    RequestQueueEntry current_request;
    char local_file_buffer[MAX_FILE_SIZE]; // Buffer privato per i dati del file
    char hash_hex_string[65]; // Buffer per l'hash esadecimale

    // Attendi che ci sia una richiesta disponibile nella coda
    // Questo semaforo viene postato dal server principale dopo aver accodato una richiesta.
    sem_wait(local_queue_fill_sem_ptr);

    // Acquisisci mutex per accedere in sicurezza alla coda condivisa
    sem_wait(local_queue_mutex_ptr);

    // Dequeue della richiesta
    if (dequeue_request(&current_request) == -1)
    {
        fprintf(stderr, "Worker PID %d: Errore inatteso: coda vuota dopo sem_wait(queue_fill_sem).\n", getpid());
        sem_post(local_queue_mutex_ptr);     // Rilascia mutex (nonostante l'errore)
        shmdt(local_shm_ptr);
        sem_close(local_worker_limit_sem_ptr);
        sem_close(local_queue_mutex_ptr);
        sem_close(local_queue_fill_sem_ptr);
        // CRITICO: In caso di errore qui, il worker deve rilasciare il semaforo worker_limit_sem_ptr
        // altrimenti il server padre rimarrà bloccato.
        sem_post(local_worker_limit_sem_ptr);
        exit(1); // Termina worker con errore
    }

    // Rilascia mutex sulla coda il prima possibile per non bloccare altre operazioni sulla coda.
    sem_post(local_queue_mutex_ptr);

    printf("Worker PID %d: Elaborazione richiesta per file: '%s' (dimensione: %zu byte) da client PID: %d.\n",
           getpid(), current_request.filename, current_request.file_size, current_request.client_pid);

    // Il worker legge il file direttamente dal disco 
    int fd = open(current_request.filename, O_RDONLY);
    if (fd == -1)
    {
        perror("Worker: Errore nell'apertura del file per l'elaborazione");
        // Invia una risposta di errore al client
        key_t client_mq_key = current_request.client_pid;
        int client_msqid = msgget(client_mq_key, 0666);
        if (client_msqid != -1)
        {
            struct ResponseMessage response;
            response.mtype = MSG_TYPE_RESPONSE;
            // Calcola la lunghezza massima del nome del file per evitare il troncamento
            const char* error_prefix = "ERROR: File '";
            const char* error_suffix = "' non accessibile.";
            size_t max_filename_len = sizeof(response.content) - strlen(error_prefix) - strlen(error_suffix) - 1; // -1 for null terminator
            
            snprintf(response.content, sizeof(response.content), "%s%.*s%s",
                     error_prefix, (int)max_filename_len, current_request.filename, error_suffix);
            msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
        }
        shmdt(local_shm_ptr);
        sem_close(local_worker_limit_sem_ptr);
        sem_close(local_queue_mutex_ptr);
        sem_close(local_queue_fill_sem_ptr);
        sem_post(local_worker_limit_sem_ptr); // Rilascia semaforo limite worker
        exit(1);
    }

    ssize_t bytes_read = read(fd, local_file_buffer, current_request.file_size);
    close(fd);

    if (bytes_read == -1 || (size_t)bytes_read != current_request.file_size)
    {
        perror("Worker: Errore nella lettura completa del file nel buffer locale");
        // Invia una risposta di errore al client
        key_t client_mq_key = current_request.client_pid;
        int client_msqid = msgget(client_mq_key, 0666);
        if (client_msqid != -1)
        {
            struct ResponseMessage response;
            response.mtype = MSG_TYPE_RESPONSE;
            // Calcola la lunghezza massima del nome del file per evitare il troncamento
            const char* error_prefix = "ERROR: Lettura file '";
            const char* error_suffix = "' fallita o incompleta.";
            size_t max_filename_len = sizeof(response.content) - strlen(error_prefix) - strlen(error_suffix) - 1; // -1 for null terminator

            snprintf(response.content, sizeof(response.content), "%s%.*s%s",
                     error_prefix, (int)max_filename_len, current_request.filename, error_suffix);
            msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
        }
        shmdt(local_shm_ptr);
        sem_close(local_worker_limit_sem_ptr);
        sem_close(local_queue_mutex_ptr);
        sem_close(local_queue_fill_sem_ptr);
        sem_post(local_worker_limit_sem_ptr); // Rilascia semaforo limite worker
        exit(1);
    }

    // Calcola hash SHA-256
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    digest_buffer(local_file_buffer, current_request.file_size, hash_bytes);
    bytes_to_hex(hash_bytes, SHA256_DIGEST_LENGTH, hash_hex_string);

    // Invia risposta al client
    key_t client_mq_key = current_request.client_pid;
    int client_msqid = msgget(client_mq_key, 0666); // Ottieni coda client esistente
    if (client_msqid == -1)
    {
        perror("Worker: Errore nel recuperare la coda messaggi del client per la risposta");
        // Non è un errore fatale per il worker, ma la risposta non verrà consegnata.
    }
    else
    {
        struct ResponseMessage response;
        response.mtype = MSG_TYPE_RESPONSE;
        strncpy(response.content, hash_hex_string, sizeof(response.content) - 1);
        response.content[sizeof(response.content) - 1] = '\0';
        if (msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
        {
            perror("Worker: Errore nell'invio della risposta al client");
        }
    }

    printf("Worker PID %d: Elaborazione completata per '%s'. Hash: %s\n", getpid(), current_request.filename, hash_hex_string);

    shmdt(local_shm_ptr);                 // Distacca memoria condivisa
    sem_close(local_worker_limit_sem_ptr);
    sem_close(local_queue_mutex_ptr);
    sem_close(local_queue_fill_sem_ptr);
    sem_post(local_worker_limit_sem_ptr); // Rilascia semaforo limite worker per permettere a un nuovo worker di avviarsi
    exit(0); // Termina processo worker con successo
}

// Funzione Principale del Server

int main(int argc, char *argv[])
{
    printf("Server: Avvio processo server (PID: %d).\n", getpid());

    // Pulisci semafori nominati, coda messaggi e SHM da esecuzioni precedenti (ignora errori)
    // Questo è cruciale per un avvio pulito se il server è crashato prima.
    sem_unlink(SEM_WORKER_LIMIT_NAME);
    sem_unlink(SEM_QUEUE_MUTEX_NAME);
    sem_unlink(SEM_QUEUE_FILL_NAME);
    
    // Tentativo di rimozione di IPC precedentemente esistenti
    int temp_msqid = msgget(SERVER_MSG_QUEUE_KEY, 0);
    if (temp_msqid != -1) {
        if (msgctl(temp_msqid, IPC_RMID, NULL) == 0) {
            printf("Server: Coda messaggi precedente (ID %d) rimossa.\n", temp_msqid);
        } else {
            perror("Server: Errore nella rimozione coda messaggi precedente");
        }
    }
    int temp_shmid = shmget(SHM_KEY, 0, 0);
    if (temp_shmid != -1) {
        if (shmctl(temp_shmid, IPC_RMID, NULL) == 0) {
            printf("Server: Memoria condivisa precedente (ID %d) rimossa.\n", temp_shmid);
        } else {
            perror("Server: Errore nella rimozione SHM precedente");
        }
    }


    // Configura gestore segnale SIGINT per pulizia graziosa
    signal(SIGINT, sigint_handler);
    // Configura gestore segnale SIGCHLD per prevenire processi zombie
    signal(SIGCHLD, sigchld_handler);

    // Imposta algoritmo di scheduling predefinito
    int initial_scheduling_algo = SCHED_FCFS;
    if (argc > 1)
    {
        if (strcmp(argv[1], "sjf") == 0)
        {
            initial_scheduling_algo = SCHED_SJF;
            printf("Server: Scheduling impostato su SJF (Shortest Job First).\n");
        }
        else if (strcmp(argv[1], "fcfs") == 0)
        {
            initial_scheduling_algo = SCHED_FCFS;
            printf("Server: Scheduling impostato su FCFS (First-Come, First-Served).\n");
        }
        else
        {
            fprintf(stderr, "Server: Attenzione: Algoritmo di scheduling sconosciuto '%s'. Uso FCFS.\n", argv[1]);
        }
    }
    else
    {
        printf("Server: Nessun algoritmo di scheduling specificato. Uso FCFS (First-Come, First-Served).\n");
    }

    // 1. Crea/Recupera coda messaggi server
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    server_msqid = msgget(server_mq_key, IPC_CREAT | 0666);
    if (server_msqid == -1)
    {
        perror("Server: Errore nella creazione della coda messaggi del server");
        exit(1);
    }
    printf("Server: Coda messaggi server creata/ottenuta con ID: %d\n", server_msqid);

    // 2. Crea/Recupera memoria condivisa
    key_t shm_key = SHM_KEY;
    shmid = shmget(shm_key, sizeof(SharedMemoryData), IPC_CREAT | 0666);
    if (shmid == -1)
    {
        perror("Server: Errore nella creazione della memoria condivisa");
        msgctl(server_msqid, IPC_RMID, NULL); // Pulisci la coda messaggi
        exit(1);
    }
    shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (shm_ptr == (void *)-1)
    {
        perror("Server: Errore nell'attaccarsi alla memoria condivisa");
        msgctl(server_msqid, IPC_RMID, NULL); // Pulisci la coda messaggi
        shmctl(shmid, IPC_RMID, NULL);       // Pulisci la SHM
        exit(1);
    }
    printf("Server: Memoria condivisa attaccata con ID: %d\n", shmid);

    // Inizializza i membri della SHM (solo all'avvio)
    shm_ptr->max_workers = MAX_WORKERS_DEFAULT;
    shm_ptr->current_workers = 0;
    shm_ptr->scheduling_algo = initial_scheduling_algo;
    shm_ptr->pending_requests_count = 0;


    // Inizializza semafori nominati (SEMPRE dopo aver pulito con unlink)
    worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, O_CREAT, 0666, MAX_WORKERS_DEFAULT);
    if (worker_limit_sem_ptr == SEM_FAILED) { perror("Server: Errore sem_open worker_limit_sem"); cleanup_ipc_resources(); exit(1); }
    printf("Server: Semaforo '%s' creato/aperto con valore iniziale %d.\n", SEM_WORKER_LIMIT_NAME, MAX_WORKERS_DEFAULT);


    queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, O_CREAT, 0666, 1);
    if (queue_mutex_ptr == SEM_FAILED) { perror("Server: Errore sem_open queue_mutex_sem"); cleanup_ipc_resources(); exit(1); }
    printf("Server: Semaforo '%s' creato/aperto.\n", SEM_QUEUE_MUTEX_NAME);


    queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, O_CREAT, 0666, 0);
    if (queue_fill_sem_ptr == SEM_FAILED) { perror("Server: Errore sem_open queue_fill_sem"); cleanup_ipc_resources(); exit(1); }
    printf("Server: Semaforo '%s' creato/aperto.\n", SEM_QUEUE_FILL_NAME);

    printf("Server: Inizializzazione SHM e semafori completata. Limite worker: %d.\n", shm_ptr->max_workers);
    printf("Server: In attesa di richieste...\n");

    // Buffer per ricevere messaggi di diversi tipi
    union
    {
        long mtype;
        struct RequestMessage req;
        struct ControlMessage ctrl;
        struct StatusRequestMessage status_req;
    } msg_buffer;

    while (!server_should_exit) // Loop principale del server
    {
        ssize_t bytes_received;
        // Ricevi qualsiasi tipo di messaggio, gestisci EINTR e EIDRM (coda rimossa)
        bytes_received = msgrcv(server_msqid, &msg_buffer, sizeof(msg_buffer) - sizeof(long), 0, 0);

        if (bytes_received == -1)
        {
            if (errno == EINTR)
            {
                if (server_should_exit) {
                    printf("Server: msgrcv interrotto da segnale, terminazione richiesta.\n");
                    break; // Esci dal loop se il segnale indica di terminare
                }
                printf("Server: msgrcv interrotto da segnale, riprovo.\n");
                continue; // Un'interruzione transitoria, riprova
            }
            else if (errno == EIDRM) // Coda di messaggi rimossa
            {
                printf("Server: La coda messaggi del server è stata rimossa. Terminazione...\n");
                server_should_exit = 1;
                break;
            }
            else
            {
                perror("Server: Errore critico nella ricezione del messaggio");
                server_should_exit = 1; // Un errore non recuperabile, esci
                break;
            }
        }
        //printf("Server: Messaggio ricevuto (tipo: %ld, dimensione: %zd byte).\n", msg_buffer.mtype, bytes_received);

        switch (msg_buffer.mtype)
        {
        case MSG_TYPE_REQUEST:
        {
            struct RequestMessage *request = &msg_buffer.req;
            printf("Server: Ricevuta richiesta da PID %d per file '%s' (dimensione: %zu byte).\n",
                   request->client_pid, request->filename, request->file_size);

            // Controlla se la dimensione del file supera MAX_FILE_SIZE (prima di accodare)
            if (request->file_size > MAX_FILE_SIZE)
            {
                fprintf(stderr, "Server: Errore: Il file '%s' (dimensione %zu byte) supera MAX_FILE_SIZE (%d byte). Richiesta scartata.\n", request->filename, request->file_size, MAX_FILE_SIZE);
                // Invia risposta di errore al client
                int client_msqid_resp = msgget(request->client_pid, 0666);
                if (client_msqid_resp != -1)
                {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    // Calcola la lunghezza massima del nome del file
                    const char* error_prefix = "ERROR: File '";
                    const char* error_suffix = "' too large.";
                    size_t max_filename_len = sizeof(response.content) - strlen(error_prefix) - strlen(error_suffix) - 1; // -1 for null terminator

                    snprintf(response.content, sizeof(response.content), "%s%.*s%s",
                             error_prefix, (int)max_filename_len, request->filename, error_suffix);
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
                continue; // Salta al prossimo messaggio
            }

            // Logica di gestione worker e coda
            // 1. Aspetta un posto disponibile per un worker (blocca se max_workers sono attivi)
            printf("Server: Attesa di un posto worker disponibile...\n");
            if (sem_wait(worker_limit_sem_ptr) == -1) {
                if (errno == EINTR) {
                    if (server_should_exit) break; // Server sta terminando
                    continue; // Altrimenti riprova
                }
                perror("Server: Errore in sem_wait(worker_limit_sem_ptr)");
                // Invia risposta di errore al client
                int client_msqid_resp = msgget(request->client_pid, 0666);
                if (client_msqid_resp != -1) {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    snprintf(response.content, sizeof(response.content), "ERROR: Server internal error on worker limit.");
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
                continue;
            }
            printf("Server: Posto worker acquisito.\n");

            // 2. Acquisisci mutex per proteggere l'accesso alla coda
            if (sem_wait(queue_mutex_ptr) == -1) {
                 if (errno == EINTR) {
                    if (server_should_exit) {sem_post(worker_limit_sem_ptr); break;} // Server sta terminando, rilascia worker_limit
                    sem_post(worker_limit_sem_ptr); // Rilascia worker_limit prima di continuare in caso di errore.
                    continue; // Altrimenti riprova
                }
                perror("Server: Errore in sem_wait(queue_mutex_ptr)");
                sem_post(worker_limit_sem_ptr); // Rilascia il permesso worker se non possiamo accedere alla coda
                 // Invia risposta di errore al client
                int client_msqid_resp = msgget(request->client_pid, 0666);
                if (client_msqid_resp != -1) {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    snprintf(response.content, sizeof(response.content), "ERROR: Server internal error on queue mutex.");
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
                continue;
            }

            // 3. Aggiungi la richiesta alla coda
            if (enqueue_request(request) == 0)
            {
                // Incrementa i worker attivi (protetto dal mutex della coda)
                shm_ptr->current_workers++;
                printf("Server: Richiesta da PID %d accodata. Richieste in sospeso: %d. Worker attivi: %d/%d.\n",
                       request->client_pid, shm_ptr->pending_requests_count, shm_ptr->current_workers, shm_ptr->max_workers);
                sem_post(queue_mutex_ptr);    // Rilascia mutex
                sem_post(queue_fill_sem_ptr); // Segnala che una richiesta è nella coda per i worker

                // 4. Crea un nuovo processo worker
                pid_t pid = fork();
                if (pid == -1)
                {
                    perror("Server: Errore nel forking del processo worker");
                    // Se il fork fallisce, dobbiamo annullare tutte le modifiche:
                    //   - Decrementare current_workers (sotto mutex)
                    //   - Rilasciare worker_limit_sem_ptr
                    //   - Decrementare queue_fill_sem_ptr (la richiesta rimane in coda ma non verrà elaborata subito)
                    sem_wait(queue_mutex_ptr);
                    shm_ptr->current_workers--;
                    printf("Server: Errore fork, worker attivi: %d/%d.\n", shm_ptr->current_workers, shm_ptr->max_workers);
                    sem_post(queue_mutex_ptr);
                    sem_post(worker_limit_sem_ptr); // Rilascia il permesso worker
                    sem_wait(queue_fill_sem_ptr); // "Consuma" il post che è stato fatto per la richiesta accodata non elaborata
                    
                    // Invia risposta di errore al client
                    int client_msqid_resp = msgget(request->client_pid, 0666);
                    if (client_msqid_resp != -1) {
                        struct ResponseMessage response;
                        response.mtype = MSG_TYPE_RESPONSE;
                        snprintf(response.content, sizeof(response.content), "ERROR: Server failed to spawn worker.");
                        msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                    }
                }
                else if (pid == 0)
                {
                    // Codice del processo figlio (worker)
                    // Il figlio non dovrebbe gestire i segnali del padre
                    signal(SIGINT, SIG_DFL); // Resetta SIGINT al default nel figlio
                    signal(SIGCHLD, SIG_DFL); // Resetta SIGCHLD al default nel figlio
                    worker_process();
                    // Il worker termina con exit(0) o exit(1)
                }
                else
                {
                    // Codice del processo padre (server principale)
                    // Continua il loop principale per ricevere nuove richieste
                }
            }
            else // Errore nell'accodamento (coda piena)
            {
                sem_post(queue_mutex_ptr); // Rilascia mutex (nonostante l'errore)
                sem_post(worker_limit_sem_ptr); // Rilascia il permesso worker che non è stato utilizzato

                // Invia un messaggio di errore al client se la coda è piena
                int client_msqid_resp = msgget(request->client_pid, 0666);
                if (client_msqid_resp != -1)
                {
                    struct ResponseMessage response;
                    response.mtype = MSG_TYPE_RESPONSE;
                    snprintf(response.content, sizeof(response.content), "ERROR: Server queue is full.");
                    msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0);
                }
            }
            break;
        }
        case MSG_TYPE_CONTROL:
        {
            struct ControlMessage *control = &msg_buffer.ctrl;
            sem_wait(queue_mutex_ptr); // Proteggi l'accesso a max_workers e regolazione semaforo

            int old_max_workers = shm_ptr->max_workers;
            int new_max_workers = control->new_max_workers;

            if (new_max_workers <= 0) {
                fprintf(stderr, "Server: Avviso: Nuovo limite worker non valido (%d). Deve essere > 0.\n", new_max_workers);
                sem_post(queue_mutex_ptr);
                break;
            }

            printf("Server: Limite massimo worker aggiornato da %d a %d.\n", old_max_workers, new_max_workers);

            // Regola il valore del semaforo worker_limit_sem_ptr
            if (new_max_workers < old_max_workers) {
                int diff = old_max_workers - new_max_workers;
                // Tentiamo di decrementare il semaforo per il numero di worker da "spegnere".
                // Se il valore corrente è già basso, sem_trywait fallirà, il che è accettabile.
                // I worker in eccesso semplicemente non saranno ripristinati.
                for (int i = 0; i < diff; i++) {
                    if (sem_trywait(worker_limit_sem_ptr) == 0) {
                        printf("Server: Decrementato semaforo worker_limit per ridurre limite.\n");
                    } else {
                        // Non possiamo decrementare ulteriormente, probabilmente già a 0 o meno worker attivi del nuovo limite.
                        break;
                    }
                }
            }
            else if (new_max_workers > old_max_workers) {
                int diff = new_max_workers - old_max_workers;
                // Incrementiamo il semaforo per il numero di nuovi worker consentiti.
                for (int i = 0; i < diff; i++) {
                    sem_post(worker_limit_sem_ptr);
                    printf("Server: Incrementato semaforo worker_limit per aumentare limite.\n");
                }
            }
            
            shm_ptr->max_workers = new_max_workers; // Aggiorna la variabile condivisa dopo aver regolato il semaforo

            sem_post(queue_mutex_ptr);
            break;
        }
        case MSG_TYPE_STATUS_REQ:
        {
            struct StatusRequestMessage *status_req = &msg_buffer.status_req;
            sem_wait(queue_mutex_ptr); // Proteggi l'accesso ai contatori
            int pending = shm_ptr->pending_requests_count;
            int active = shm_ptr->current_workers;
            int max_w = shm_ptr->max_workers;
            char *sched_algo_name = (shm_ptr->scheduling_algo == SCHED_FCFS) ? "FCFS" : "SJF";
            sem_post(queue_mutex_ptr);

            // Ottieni la coda del client (il client deve averla creata con la sua PID come chiave)
            int client_msqid_resp = msgget(status_req->client_pid, 0666);
            if (client_msqid_resp == -1)
            {
                perror("Server: Errore nel recuperare la coda messaggi del client per lo stato");
            }
            else
            {
                struct ResponseMessage response;
                response.mtype = MSG_TYPE_RESPONSE;
                snprintf(response.content, sizeof(response.content),
                         "Stato: RichiesteInCoda=%d, WorkerAttivi=%d/%d, Schedulazione=%s",
                         pending, active, max_w, sched_algo_name);
                if (msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
                {
                    perror("Server: Errore nell'invio della risposta di stato al client");
                }
            }
            printf("Server: Stato inviato a PID %d.\n", status_req->client_pid);
            break;
        }
        default:
            fprintf(stderr, "Server: Tipo di messaggio sconosciuto ricevuto: %ld (dimensione: %zd byte).\n", msg_buffer.mtype, bytes_received);
            break;
        }
    }

    printf("Server: Ciclo principale terminato. Avvio pulizia finale...\n");
    cleanup_ipc_resources(); // Pulisci tutte le risorse IPC all'uscita

    return 0;
}