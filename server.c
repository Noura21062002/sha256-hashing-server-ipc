#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>    // Per S_IRUSR | S_IWUSR
#include <unistd.h>      // Per fork, getpid, read, close
#include <fcntl.h>       // Per open, O_RDONLY
#include <openssl/evp.h> // Per API EVP (hashing moderno OpenSSL)
#include <openssl/sha.h> // Per SHA256_DIGEST_LENGTH (definisce la dimensione dell'hash SHA-256)
#include <semaphore.h>   // Per semafori POSIX
#include <sys/wait.h>    // Per waitpid
#include <signal.h>      // Per gestione segnali (SIGCHLD)

// --- Costanti per IPC ---
#define SERVER_MSG_QUEUE_KEY 1234
#define SHM_KEY 5678
#define MAX_FILE_SIZE (256 * 1024) // 256 KB - Ridotto per compatibilità con limiti di SHM su alcuni sistemi
#define MAX_PENDING_REQUESTS 100   // Dimensione massima della coda di richieste
#define MAX_WORKERS_DEFAULT 5      // Limite di worker predefinito

// --- Nomi dei Semafori Nominati ---
#define SEM_WORKER_LIMIT_NAME "/worker_limit_sem"
#define SEM_QUEUE_MUTEX_NAME "/queue_mutex_sem"
#define SEM_QUEUE_FILL_NAME "/queue_fill_sem"
#define SEM_SHM_INIT_NAME "/shm_init_sem" // Semaforo per inizializzazione SHM

// --- Tipi di Messaggio ---
#define MSG_TYPE_REQUEST 1    // Richiesta di calcolo hash dal client
#define MSG_TYPE_CONTROL 2    // Messaggio di controllo (es. cambio limite worker)
#define MSG_TYPE_STATUS_REQ 3 // Richiesta di stato del server
#define MSG_TYPE_RESPONSE 4   // Risposta del server al client (hash o stato)

// --- Algoritmi di Schedulazione ---
#define SCHED_FCFS 0 // First-Come, First-Served
#define SCHED_SJF 1  // Shortest Job First (by file size)

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

// Struttura per una singola voce nella coda di richieste condivisa
typedef struct
{
    pid_t client_pid;
    char filename[256];
    size_t file_size;
} RequestQueueEntry;

// --- Struttura della Memoria Condivisa ---
// Contiene dati di sincronizzazione, configurazione e la coda di richieste.
// I semafori nominati non sono parte della SHM, ma sono referenziati tramite nomi.
typedef struct
{
    int max_workers;                     // Limite configurabile di worker concorrenti
    volatile int current_workers;        // Numero di processi worker attivi (volatile per accesso concorrente)
    int scheduling_algo;                 // Algoritmo di schedulazione (FCFS o SJF)
    volatile int pending_requests_count; // Numero di richieste in coda (volatile)

    RequestQueueEntry request_queue[MAX_PENDING_REQUESTS];
    int queue_head; // Indice del primo elemento nella coda
    int queue_tail; // Indice del prossimo slot disponibile

    // Buffer per il trasferimento dei dati del file.
    // Un solo file può essere in SHM alla volta. I worker devono copiarlo.
    char file_data_buffer[MAX_FILE_SIZE];
    size_t file_data_current_size; // Dimensione del file attualmente nel buffer
    pid_t file_data_client_pid;    // PID del client il cui file è attualmente nel buffer
    char file_data_filename[256];  // Nome del file attualmente nel buffer
} SharedMemoryData;

// Puntatore globale alla memoria condivisa
SharedMemoryData *shm_ptr;
int server_msqid;
int shmid;

// Puntatori globali ai semafori nominati
sem_t *worker_limit_sem_ptr;
sem_t *queue_mutex_ptr;
sem_t *queue_fill_sem_ptr;
sem_t *shm_init_sem_ptr;

// --- Funzioni di Utilità per SHA-256 ---

/**
 * @brief Calcola l'impronta SHA-256 di un buffer di memoria usando l'API EVP.
 * @param buffer Puntatore al buffer contenente i dati.
 * @param len Lunghezza dei dati nel buffer.
 * @param hash Array di 32 byte per memorizzare l'impronta SHA-256.
 */
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

/**
 * @brief Converte un array di byte in una stringa esadecimale.
 * @param bytes Array di byte da convertire.
 * @param len Lunghezza dell'array di byte.
 * @param hex_string Buffer per memorizzare la stringa esadecimale (deve essere di dimensione 2*len + 1).
 */
void bytes_to_hex(unsigned char *bytes, int len, char *hex_string)
{
    for (int i = 0; i < len; i++)
    {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    hex_string[len * 2] = '\0'; // Aggiungi il terminatore null
}

// --- Funzioni di Gestione Coda ---

/**
 * @brief Aggiunge una richiesta alla coda condivisa.
 * Necessita che queue_mutex_ptr sia già acquisito.
 * @param request La richiesta da aggiungere.
 * @return 0 in caso di successo, -1 se la coda è piena.
 */
int enqueue_request(const struct RequestMessage *request)
{
    if (shm_ptr->pending_requests_count >= MAX_PENDING_REQUESTS)
    {
        fprintf(stderr, "Server: Coda di richieste piena, scarto la richiesta da PID %d.\n", request->client_pid);
        return -1;
    }

    shm_ptr->request_queue[shm_ptr->queue_tail] = (RequestQueueEntry){
        .client_pid = request->client_pid,
        .file_size = request->file_size};
    strncpy(shm_ptr->request_queue[shm_ptr->queue_tail].filename, request->filename, sizeof(shm_ptr->request_queue[shm_ptr->queue_tail].filename) - 1);
    shm_ptr->request_queue[shm_ptr->queue_tail].filename[sizeof(shm_ptr->request_queue[shm_ptr->queue_tail].filename) - 1] = '\0';

    shm_ptr->queue_tail = (shm_ptr->queue_tail + 1) % MAX_PENDING_REQUESTS;
    shm_ptr->pending_requests_count++;

    // Se SJF, riordina la coda
    if (shm_ptr->scheduling_algo == SCHED_SJF && shm_ptr->pending_requests_count > 1)
    {
        // Implementazione semplice di insertion sort per mantenere la coda ordinata
        // Questo è un approccio semplificato e potrebbe non essere efficiente per code molto grandi.
        // Per una vera implementazione SJF, si userebbe una priority queue.
        for (int i = 0; i < shm_ptr->pending_requests_count - 1; i++)
        {
            int current_idx = (shm_ptr->queue_head + i) % MAX_PENDING_REQUESTS;
            int next_idx = (shm_ptr->queue_head + i + 1) % MAX_PENDING_REQUESTS;

            if (shm_ptr->request_queue[current_idx].file_size > shm_ptr->request_queue[next_idx].file_size)
            {
                // Swap
                RequestQueueEntry temp = shm_ptr->request_queue[current_idx];
                shm_ptr->request_queue[current_idx] = shm_ptr->request_queue[next_idx];
                shm_ptr->request_queue[next_idx] = temp;
            }
        }
    }
    return 0;
}

/**
 * @brief Rimuove e restituisce la prossima richiesta dalla coda condivisa.
 * Necessita che queue_mutex_ptr sia già acquisito e che ci siano richieste.
 * @param entry Puntatore alla struttura dove copiare la richiesta.
 * @return 0 in caso di successo, -1 se la coda è vuota.
 */
int dequeue_request(RequestQueueEntry *entry)
{
    if (shm_ptr->pending_requests_count == 0)
    {
        return -1; // Coda vuota
    }

    *entry = shm_ptr->request_queue[shm_ptr->queue_head];
    shm_ptr->queue_head = (shm_ptr->queue_head + 1) % MAX_PENDING_REQUESTS;
    shm_ptr->pending_requests_count--;
    return 0;
}

// --- Gestore Segnali ---

/**
 * @brief Gestore del segnale SIGCHLD per prevenire processi zombie.
 */
void sigchld_handler(int signo)
{
    int status;
    pid_t pid;
    // Usa WNOHANG per non bloccare se non ci sono figli terminati
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        // Processo figlio terminato. Decrementa il contatore dei worker attivi.
        // Proteggi l'accesso a current_workers con il mutex della coda,
        // anche se non stiamo modificando la coda stessa, per consistenza.
        sem_wait(queue_mutex_ptr); // Usa il puntatore al semaforo nominato
        shm_ptr->current_workers--;
        sem_post(queue_mutex_ptr); // Usa il puntatore al semaforo nominato
        printf("Server: Processo worker PID %d terminato. Worker attivi: %d.\n", pid, shm_ptr->current_workers);
    }
}

// --- Funzione del Processo Worker ---

/**
 * @brief Funzione eseguita da ogni processo worker figlio.
 * Elabora una richiesta dalla coda, calcola l'hash e invia la risposta.
 */
void worker_process()
{
    // Ogni worker deve attaccarsi alla memoria condivisa
    SharedMemoryData *local_shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (local_shm_ptr == (void *)-1)
    {
        perror("Worker: Errore nell'attaccamento alla memoria condivisa");
        exit(1);
    }

    // Ogni worker deve aprire i semafori nominati
    sem_t *local_worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, 0);
    sem_t *local_queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, 0);
    sem_t *local_queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, 0);

    if (local_worker_limit_sem_ptr == SEM_FAILED || local_queue_mutex_ptr == SEM_FAILED || local_queue_fill_sem_ptr == SEM_FAILED)
    {
        perror("Worker: Errore nell'apertura dei semafori nominati");
        shmdt(local_shm_ptr);
        exit(1);
    }

    RequestQueueEntry current_request;
    char local_file_buffer[MAX_FILE_SIZE]; // Buffer privato per il file

    // Attendi una richiesta nella coda
    sem_wait(local_queue_fill_sem_ptr); // Attende che ci sia almeno una richiesta disponibile

    // Acquisisci il mutex per accedere alla coda e al buffer condiviso
    sem_wait(local_queue_mutex_ptr);

    // Dequeue la richiesta
    if (dequeue_request(&current_request) == -1)
    {
        fprintf(stderr, "Worker: Errore inatteso: coda vuota dopo sem_wait.\n");
        sem_post(local_queue_mutex_ptr); // Rilascia il mutex
        shmdt(local_shm_ptr);
        sem_close(local_worker_limit_sem_ptr);
        sem_close(local_queue_mutex_ptr);
        sem_close(local_queue_fill_sem_ptr);
        exit(1); // Termina il worker
    }

    // Copia i dati del file dal buffer condiviso al buffer privato del worker
    // Questo è CRUCIALE per la concorrenza, per evitare che un nuovo client sovrascriva
    // il buffer condiviso mentre questo worker lo sta ancora leggendo.
    // Si verifica una corrispondenza per assicurarsi che i dati in SHM siano quelli attesi per questa richiesta.
    if (current_request.client_pid != local_shm_ptr->file_data_client_pid ||
        strcmp(current_request.filename, local_shm_ptr->file_data_filename) != 0 ||
        current_request.file_size != local_shm_ptr->file_data_current_size)
    {
        fprintf(stderr, "Worker PID %d: Attenzione: i dati del file in SHM non corrispondono alla richiesta dequeued. Questo può accadere con alta concorrenza se il client invia la richiesta prima che il server abbia copiato il file. La richiesta verrà scartata.\n", getpid());

        // Invia una risposta di errore al client
        char error_hash[65];
        strcpy(error_hash, "ERROR: SHM_DATA_MISMATCH");
        key_t client_mq_key = current_request.client_pid;
        int client_msqid = msgget(client_mq_key, 0666);
        if (client_msqid == -1)
        {
            perror("Worker: Errore nel recupero della coda di messaggi del client (per errore)");
        }
        else
        {
            struct ResponseMessage response;
            response.mtype = MSG_TYPE_RESPONSE;
            strcpy(response.content, error_hash);
            if (msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
            {
                perror("Worker: Errore nell'invio della risposta di errore al client");
            }
        }
        sem_post(local_queue_mutex_ptr);      // Rilascia il mutex
        sem_post(local_worker_limit_sem_ptr); // Rilascia il semaforo limite worker
        shmdt(local_shm_ptr);
        sem_close(local_worker_limit_sem_ptr);
        sem_close(local_queue_mutex_ptr);
        sem_close(local_queue_fill_sem_ptr);
        exit(1); // Termina il worker
    }

    memcpy(local_file_buffer, local_shm_ptr->file_data_buffer, current_request.file_size);
    printf("Worker PID %d: Elaborazione richiesta per file '%s' (dimensione: %zu bytes).\n", getpid(), current_request.filename, current_request.file_size);

    sem_post(local_queue_mutex_ptr); // Rilascia il mutex

    // Calcola l'hash SHA-256
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    char hash_hex_string[65];

    if (current_request.file_size > MAX_FILE_SIZE)
    {
        // Questo caso dovrebbe essere già gestito dal client, ma per sicurezza.
        fprintf(stderr, "Worker PID %d: Errore: Dimensione file (%zu bytes) supera il limite di memoria condivisa (%d bytes).\n", getpid(), current_request.file_size, MAX_FILE_SIZE);
        strcpy(hash_hex_string, "ERROR: FILE_TOO_LARGE");
    }
    else
    {
        digest_buffer(local_file_buffer, current_request.file_size, hash_bytes);
        bytes_to_hex(hash_bytes, SHA256_DIGEST_LENGTH, hash_hex_string);
    }

    // Invia la risposta al client
    key_t client_mq_key = current_request.client_pid;
    int client_msqid = msgget(client_mq_key, 0666); // Ottieni la coda esistente del client
    if (client_msqid == -1)
    {
        perror("Worker: Errore nel recupero della coda di messaggi del client");
    }
    else
    {
        struct ResponseMessage response;
        response.mtype = MSG_TYPE_RESPONSE;
        strcpy(response.content, hash_hex_string);
        if (msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
        {
            perror("Worker: Errore nell'invio della risposta al client");
        }
    }

    printf("Worker PID %d: Completata elaborazione per '%s'. Hash: %s\n", getpid(), current_request.filename, hash_hex_string);

    shmdt(local_shm_ptr);                 // Scollega la memoria condivisa
    sem_post(local_worker_limit_sem_ptr); // Rilascia il semaforo limite worker
    sem_close(local_worker_limit_sem_ptr);
    sem_close(local_queue_mutex_ptr);
    sem_close(local_queue_fill_sem_ptr);
    exit(0); // Termina il processo worker
}

// --- Funzioni di Pulizia Risorse IPC ---

/**
 * @brief Funzione per la pulizia delle risorse IPC (coda di messaggi, memoria condivisa, semafori).
 */
void cleanup_ipc_resources()
{
    printf("Server: Avvio pulizia risorse IPC...\n");

    // Chiudi e scollega i semafori nominati
    // Non controlliamo SEM_FAILED qui, perché sem_unlink ignora EACCES e ENOENT.
    // Li unlinkeremo sempre per garantire pulizia.
    sem_unlink(SEM_WORKER_LIMIT_NAME);
    sem_unlink(SEM_QUEUE_MUTEX_NAME);
    sem_unlink(SEM_QUEUE_FILL_NAME);
    sem_unlink(SEM_SHM_INIT_NAME);

    // Chiudi i descrittori dei semafori se sono stati aperti con successo
    if (worker_limit_sem_ptr != SEM_FAILED)
        sem_close(worker_limit_sem_ptr);
    if (queue_mutex_ptr != SEM_FAILED)
        sem_close(queue_mutex_ptr);
    if (queue_fill_sem_ptr != SEM_FAILED)
        sem_close(queue_fill_sem_ptr);
    if (shm_init_sem_ptr != SEM_FAILED)
        sem_close(shm_init_sem_ptr);

    if (shm_ptr != (void *)-1 && shm_ptr != NULL)
    {
        shmdt(shm_ptr); // Scollega la memoria condivisa
    }

    if (shmid != -1)
    {
        shmctl(shmid, IPC_RMID, NULL); // Rimuovi la memoria condivisa
    }

    if (server_msqid != -1)
    {
        msgctl(server_msqid, IPC_RMID, NULL); // Rimuovi la coda di messaggi del server
    }
    printf("Server: Pulizia risorse IPC completata.\n");
}

/**
 * @brief Gestore del segnale SIGINT (Ctrl+C) per una pulizia ordinata.
 */
void sigint_handler(int signo)
{
    printf("\nServer: Segnale SIGINT ricevuto. Terminazione...\n");
    cleanup_ipc_resources();
    exit(0);
}

// --- Funzione Main del Server ---

int main(int argc, char *argv[])
{
    // Pulisci i semafori nominati all'avvio per garantire uno stato pulito.
    // Ignora gli errori, potrebbero non esistere ancora.
    sem_unlink(SEM_WORKER_LIMIT_NAME);
    sem_unlink(SEM_QUEUE_MUTEX_NAME);
    sem_unlink(SEM_QUEUE_FILL_NAME);
    sem_unlink(SEM_SHM_INIT_NAME);

    // Pulisci anche la coda di messaggi del server e la memoria condivisa all'avvio.
    // Questo garantisce un avvio completamente pulito di tutte le risorse IPC.
    // Ignora gli errori se le risorse non esistono.
    int temp_msqid = msgget(SERVER_MSG_QUEUE_KEY, 0);
    if (temp_msqid != -1)
    {
        msgctl(temp_msqid, IPC_RMID, NULL);
    }
    int temp_shmid = shmget(SHM_KEY, 0, 0); // Ottieni l'ID senza creare/attaccare
    if (temp_shmid != -1)
    {
        shmctl(temp_shmid, IPC_RMID, NULL);
    }

    // Configura il gestore del segnale SIGINT per una pulizia ordinata
    signal(SIGINT, sigint_handler);
    // Configura il gestore del segnale SIGCHLD per prevenire i processi zombie
    signal(SIGCHLD, sigchld_handler);

    // Imposta l'algoritmo di schedulazione predefinito
    int initial_scheduling_algo = SCHED_FCFS;
    if (argc > 1)
    {
        if (strcmp(argv[1], "sjf") == 0)
        {
            initial_scheduling_algo = SCHED_SJF;
            printf("Server: Schedulazione impostata su SJF (Shortest Job First).\n");
        }
        else if (strcmp(argv[1], "fcfs") == 0)
        {
            initial_scheduling_algo = SCHED_FCFS;
            printf("Server: Schedulazione impostata su FCFS (First-Come, First-Served).\n");
        }
        else
        {
            fprintf(stderr, "Server: Avviso: Algoritmo di schedulazione sconosciuto '%s'. Usando FCFS.\n", argv[1]);
        }
    }
    else
    {
        printf("Server: Nessun algoritmo di schedulazione specificato. Usando FCFS (First-Come, First-Served).\n");
    }

    printf("Server: Avvio del server SHA-256.\n");

    // 1. Creazione/Recupero della coda di messaggi del server
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    server_msqid = msgget(server_mq_key, IPC_CREAT | 0666);
    if (server_msqid == -1)
    {
        perror("Server: Errore nella creazione della coda di messaggi del server");
        exit(1);
    }
    printf("Server: Coda di messaggi del server creata/ottenuta con ID: %d\n", server_msqid);

    // 2. Creazione/Recupero della memoria condivisa
    key_t shm_key = SHM_KEY;
    shmid = shmget(shm_key, sizeof(SharedMemoryData), IPC_CREAT | 0666);
    if (shmid == -1)
    {
        perror("Server: Errore nella creazione della memoria condivisa");
        msgctl(server_msqid, IPC_RMID, NULL);
        exit(1);
    }
    shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (shm_ptr == (void *)-1)
    {
        perror("Server: Errore nell'attaccamento alla memoria condivisa");
        msgctl(server_msqid, IPC_RMID, NULL);
        shmctl(shmid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Server: Memoria condivisa attaccata con ID: %d\n", shmid);

    // 3. Inizializzazione della memoria condivisa e dei semafori nominati
    // Usiamo un semaforo nominato per garantire che l'inizializzazione avvenga una sola volta.
    // Dato che abbiamo unlinked tutti i semafori all'inizio, possiamo sempre usare O_CREAT.
    shm_init_sem_ptr = sem_open(SEM_SHM_INIT_NAME, O_CREAT, 0666, 1);
    if (shm_init_sem_ptr == SEM_FAILED)
    {
        perror("Server: Errore nella creazione/apertura del semaforo di inizializzazione SHM");
        cleanup_ipc_resources();
        exit(1);
    }

    sem_wait(shm_init_sem_ptr); // Acquisisci il semaforo per l'inizializzazione

    // Controlla se è la prima volta che la memoria condivisa viene inizializzata
    // (un modo semplice è controllare un valore noto, es. max_workers == 0)
    // Questo check è ancora utile per inizializzare i campi della SHM stessa.
    int first_init = (shm_ptr->max_workers == 0);

    if (first_init)
    {
        printf("Server: Inizializzazione della memoria condivisa e apertura dei semafori nominati.\n");
        // Apri/crea i semafori nominati. Saranno sempre creati nuovi qui.
        worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, O_CREAT, 0666, MAX_WORKERS_DEFAULT);
        queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, O_CREAT, 0666, 1);
        queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, O_CREAT, 0666, 0);

        if (worker_limit_sem_ptr == SEM_FAILED || queue_mutex_ptr == SEM_FAILED || queue_fill_sem_ptr == SEM_FAILED)
        {
            perror("Server: Errore nell'apertura/creazione dei semafori nominati");
            sem_post(shm_init_sem_ptr); // Rilascia il semaforo di inizializzazione
            cleanup_ipc_resources();
            exit(1);
        }

        shm_ptr->max_workers = MAX_WORKERS_DEFAULT;
        shm_ptr->current_workers = 0;
        shm_ptr->scheduling_algo = initial_scheduling_algo;
        shm_ptr->pending_requests_count = 0;
        shm_ptr->queue_head = 0;
        shm_ptr->queue_tail = 0;
        shm_ptr->file_data_current_size = 0;
        shm_ptr->file_data_client_pid = 0;
        memset(shm_ptr->file_data_filename, 0, sizeof(shm_ptr->file_data_filename));
    }
    else
    {
        printf("Server: Memoria condivisa già inizializzata. Apertura dei semafori esistenti.\n");
        // Se la SHM esiste già, apri semplicemente i semafori esistenti.
        // Dato che li abbiamo unlinked all'inizio, questo ramo dovrebbe essere raggiunto solo
        // se il server è stato riavviato molto velocemente dopo un crash e non tutti gli unlink
        // sono stati processati, o se c'è un'altra istanza.
        // Per sicurezza, li apriamo senza O_CREAT qui, ma la pulizia iniziale è la chiave.
        worker_limit_sem_ptr = sem_open(SEM_WORKER_LIMIT_NAME, 0); // 0 per non creare
        queue_mutex_ptr = sem_open(SEM_QUEUE_MUTEX_NAME, 0);
        queue_fill_sem_ptr = sem_open(SEM_QUEUE_FILL_NAME, 0);

        if (worker_limit_sem_ptr == SEM_FAILED || queue_mutex_ptr == SEM_FAILED || queue_fill_sem_ptr == SEM_FAILED)
        {
            perror("Server: Errore nell'apertura dei semafori nominati esistenti");
            sem_post(shm_init_sem_ptr); // Rilascia il semaforo di inizializzazione
            cleanup_ipc_resources();
            exit(1);
        }
    }
    sem_post(shm_init_sem_ptr); // Rilascia il semaforo di inizializzazione
    // Non chiudere shm_init_sem_ptr qui, lo chiuderemo e unlinkeremo in cleanup_ipc_resources.

    printf("Server: In attesa di richieste (Worker limit: %d)...\n", shm_ptr->max_workers);

    // Buffer per ricevere messaggi di diversi tipi
    union
    {
        long mtype; // Per leggere solo il tipo di messaggio
        struct RequestMessage req;
        struct ControlMessage ctrl;
        struct StatusRequestMessage status_req;
    } msg_buffer;

    while (1)
    {
        // Ricevi qualsiasi tipo di messaggio
        ssize_t bytes_received = msgrcv(server_msqid, &msg_buffer, sizeof(msg_buffer) - sizeof(long), 0, 0);
        if (bytes_received == -1)
        {
            perror("Server: Errore nella ricezione del messaggio");
            continue;
        }

        switch (msg_buffer.mtype)
        {
        case MSG_TYPE_REQUEST:
        {
            struct RequestMessage *request = &msg_buffer.req;
            printf("Server: Ricevuta richiesta da PID %d per file '%s' (dimensione: %zu bytes).\n",
                   request->client_pid, request->filename, request->file_size);

            // Copia i metadati del file nella SHM per il worker
            sem_wait(queue_mutex_ptr); // Proteggi l'accesso al buffer SHM e alla coda
            // Assicurati che il buffer SHM sia pronto per il nuovo file
            shm_ptr->file_data_current_size = request->file_size;
            shm_ptr->file_data_client_pid = request->client_pid;
            strncpy(shm_ptr->file_data_filename, request->filename, sizeof(shm_ptr->file_data_filename) - 1);
            shm_ptr->file_data_filename[sizeof(shm_ptr->file_data_filename) - 1] = '\0';

            // Aggiungi la richiesta alla coda
            if (enqueue_request(request) == 0)
            {
                printf("Server: Richiesta da PID %d accodata. Richieste pendenti: %d.\n", request->client_pid, shm_ptr->pending_requests_count);
                sem_post(queue_mutex_ptr);    // Rilascia il mutex
                sem_post(queue_fill_sem_ptr); // Segnala che c'è una richiesta in coda

                // Tenta di acquisire il semaforo per il limite dei worker
                // Questo bloccherà se il limite massimo di worker è stato raggiunto
                sem_wait(worker_limit_sem_ptr);

                // Acquisito il semaforo, possiamo creare un nuovo worker
                sem_wait(queue_mutex_ptr); // Proteggi current_workers
                shm_ptr->current_workers++;
                printf("Server: Creazione nuovo worker. Worker attivi: %d.\n", shm_ptr->current_workers);
                sem_post(queue_mutex_ptr);

                pid_t pid = fork();
                if (pid == -1)
                {
                    perror("Server: Errore nella fork del processo worker");
                    sem_wait(queue_mutex_ptr); // Proteggi current_workers
                    shm_ptr->current_workers--;
                    sem_post(queue_mutex_ptr);
                    sem_post(worker_limit_sem_ptr); // Rilascia il semaforo se fork fallisce
                }
                else if (pid == 0)
                {
                    // Codice del processo figlio (worker)
                    worker_process();
                    // Il worker termina con exit(0) o exit(1)
                }
                else
                {
                    // Codice del processo padre (server principale)
                    // Continua il ciclo principale per ricevere nuove richieste
                }
            }
            else
            {
                sem_post(queue_mutex_ptr); // Rilascia il mutex se la coda è piena
                // Invia un messaggio di errore al client se la coda è piena
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
            sem_wait(queue_mutex_ptr); // Proteggi l'accesso a max_workers
            int old_max_workers = shm_ptr->max_workers;
            shm_ptr->max_workers = control->new_max_workers;
            printf("Server: Limite massimo worker aggiornato da %d a %d.\n", old_max_workers, shm_ptr->max_workers);

            // Se il nuovo limite è maggiore, rilascia il semaforo per consentire più worker
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
            sem_wait(queue_mutex_ptr); // Proteggi l'accesso ai contatori
            int pending = shm_ptr->pending_requests_count;
            int active = shm_ptr->current_workers;
            int max_w = shm_ptr->max_workers;
            char *sched_algo_name = (shm_ptr->scheduling_algo == SCHED_FCFS) ? "FCFS" : "SJF";
            sem_post(queue_mutex_ptr);

            key_t client_mq_key = status_req->client_pid;
            int client_msqid_resp = msgget(client_mq_key, 0666);
            if (client_msqid_resp == -1)
            {
                perror("Server: Errore nel recupero della coda di messaggi del client per stato");
            }
            else
            {
                struct ResponseMessage response;
                response.mtype = MSG_TYPE_RESPONSE;
                snprintf(response.content, sizeof(response.content),
                         "Stato: Pendenti=%d, Attivi=%d/%d, Sched=%s",
                         pending, active, max_w, sched_algo_name);
                if (msgsnd(client_msqid_resp, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1)
                {
                    perror("Server: Errore nell'invio della risposta di stato al client");
                }
            }
            printf("Server: Inviato stato a PID %d.\n", status_req->client_pid);
            break;
        }
        default:
            fprintf(stderr, "Server: Tipo di messaggio sconosciuto ricevuto: %ld\n", msg_buffer.mtype);
            break;
        }
    }

    // Questa parte del codice non è raggiungibile in un ciclo infinito,
    // ma è inclusa per completezza. La pulizia avviene tramite SIGINT handler.
    cleanup_ipc_resources();
    return 0;
}