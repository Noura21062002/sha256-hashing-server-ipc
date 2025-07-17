#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h> // Per S_IRUSR | S_IWUSR - Corretto da sys/stat.n
#include <unistd.h>   // Per fork, getpid, read, close
#include <fcntl.h>    // Per open, O_RDONLY
#include <openssl/sha.h> // Per SHA256_CTX, SHA256_Init, SHA256_Update, SHA256_Final

// --- Costanti per IPC ---
// Chiave della coda di messaggi del server (coda di richieste)
#define SERVER_MSG_QUEUE_KEY 1234
// Chiave della memoria condivisa
#define SHM_KEY 5678
// Dimensione massima del file trasferibile tramite memoria condivisa (1 MB)
#define MAX_FILE_SIZE (1024 * 1024)

// --- Strutture dei messaggi ---

// Struttura del messaggio di richiesta (dal client al server)
struct RequestMessage {
    long mtype;             // Tipo di messaggio (deve essere > 0)
    pid_t client_pid;       // PID del client per identificare la sua coda di risposta
    char filename[256];     // Nome originale del file
};

// Struttura del messaggio di risposta (dal server al client)
struct ResponseMessage {
    long mtype;             // Tipo di messaggio (deve essere > 0)
    char sha256_hash[65];   // Impronta SHA-256 in formato esadecimale (64 caratteri + terminatore null)
};

// --- Struttura della memoria condivisa ---

// Contiene la dimensione dei dati e i dati effettivi del file
typedef struct {
    size_t data_size;           // Dimensione dei dati del file
    char data[MAX_FILE_SIZE];   // Buffer per i dati del file
} SharedMemoryData;

// --- Funzioni di utilità per SHA-256 ---

/**
 * @brief Calcola l'impronta SHA-256 di un buffer di memoria.
 * @param buffer Puntatore al buffer contenente i dati.
 * @param len Lunghezza dei dati nel buffer.
 * @param hash Array di 32 byte per memorizzare l'impronta SHA-256.
 */
void digest_buffer(const char *buffer, size_t len, unsigned char *hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buffer, len);
    SHA256_Final(hash, &ctx);
}

/**
 * @brief Converte un array di byte in una stringa esadecimale.
 * @param bytes Array di byte da convertire.
 * @param len Lunghezza dell'array di byte.
 * @param hex_string Buffer per memorizzare la stringa esadecimale (deve essere di dimensione 2*len + 1).
 */
void bytes_to_hex(unsigned char *bytes, int len, char *hex_string) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    hex_string[len * 2] = '\0'; // Aggiungi il terminatore null
}

// --- Codice del Server ---

/**
 * @brief Funzione principale del server.
 * Inizializza la coda di messaggi e la memoria condivisa, quindi attende le richieste dei client.
 */
void run_server() {
    printf("Server: Avvio del server SHA-256.\n");

    // 1. Creazione/Recupero della coda di messaggi del server (per le richieste in ingresso)
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, IPC_CREAT | 0666); // IPC_CREAT se non esiste, 0666 per permessi RW
    if (server_msqid == -1) {
        perror("Server: Errore nella creazione della coda di messaggi del server");
        exit(1);
    }
    printf("Server: Coda di messaggi del server creata/ottenuta con ID: %d\n", server_msqid);

    // 2. Creazione/Recupero della memoria condivisa
    key_t shm_key = SHM_KEY;
    int shmid = shmget(shm_key, sizeof(SharedMemoryData), IPC_CREAT | 0666); // IPC_CREAT se non esiste
    if (shmid == -1) {
        perror("Server: Errore nella creazione della memoria condivisa");
        // Tentativo di pulizia se la coda di messaggi è stata creata
        msgctl(server_msqid, IPC_RMID, NULL);
        exit(1);
    }
    // Attaccamento della memoria condivisa al nostro spazio di indirizzamento
    SharedMemoryData *shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (shm_ptr == (void *)-1) {
        perror("Server: Errore nell'attaccamento alla memoria condivisa");
        // Tentativo di pulizia
        msgctl(server_msqid, IPC_RMID, NULL);
        shmctl(shmid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Server: Memoria condivisa attaccata con ID: %d\n", shmid);

    printf("Server: In attesa di richieste...\n");

    struct RequestMessage request;
    while (1) {
        // Ricevi una richiesta dal client dalla coda di messaggi del server
        // mtype = 1 per ricevere messaggi di tipo "richiesta"
        if (msgrcv(server_msqid, &request, sizeof(struct RequestMessage) - sizeof(long), 1, 0) == -1) {
            perror("Server: Errore nella ricezione della richiesta");
            continue; // Continua ad attendere altre richieste
        }
        printf("Server: Ricevuta richiesta da PID %d per file '%s'.\n", request.client_pid, request.filename);

        // Processa il file dalla memoria condivisa
        unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
        char hash_hex_string[65];

        // Verifica che la dimensione del file non superi il limite della memoria condivisa
        if (shm_ptr->data_size > MAX_FILE_SIZE) {
            fprintf(stderr, "Server: Errore: Dimensione file (%zu bytes) supera il limite di memoria condivisa (%d bytes).\n", shm_ptr->data_size, MAX_FILE_SIZE);
            strcpy(hash_hex_string, "ERROR: FILE_TOO_LARGE"); // Invia un messaggio di errore come hash
        } else {
            // Calcola l'impronta SHA-256 dal buffer in memoria condivisa
            digest_buffer(shm_ptr->data, shm_ptr->data_size, hash_bytes);
            // Converti i byte dell'hash in una stringa esadecimale
            bytes_to_hex(hash_bytes, SHA256_DIGEST_LENGTH, hash_hex_string);
            printf("Server: SHA-256 per '%s': %s\n", request.filename, hash_hex_string);
        }

        // Messaggio di conferma che l'hash è stato calcolato e si sta per inviare la risposta
        printf("Server: Hash calcolato per '%s'. Preparo l'invio della risposta al client PID %d.\n", request.filename, request.client_pid);


        // Invia la risposta alla coda di messaggi del client
        // La chiave della coda di risposta del client è il suo PID
        key_t client_mq_key = request.client_pid;
        int client_msqid = msgget(client_mq_key, 0666); // Ottieni la coda esistente del client
        if (client_msqid == -1) {
            perror("Server: Errore nel recupero della coda di messaggi del client. Il client potrebbe essere uscito.");
            continue; // Il client potrebbe aver terminato o rimosso la sua coda
        }

        struct ResponseMessage response;
        response.mtype = 1; // Tipo di messaggio standard per la risposta
        strcpy(response.sha256_hash, hash_hex_string);

        // Invia la risposta al client
        if (msgsnd(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 0) == -1) {
            perror("Server: Errore nell'invio della risposta al client");
        }
    }

    // Questa parte del codice è irraggiungibile in un ciclo infinito,
    // ma è inclusa per mostrare la pulizia delle risorse.
    shmdt(shm_ptr); // Scollega la memoria condivisa
    shmctl(shmid, IPC_RMID, NULL); // Rimuovi la memoria condivisa
    msgctl(server_msqid, IPC_RMID, NULL); // Rimuovi la coda di messaggi del server
}

// --- Codice del Client ---

/**
 * @brief Funzione principale del client.
 * Si connette al server, invia il file tramite memoria condivisa e riceve l'impronta SHA-256.
 * @param filepath Percorso del file da processare.
 */
void run_client(const char *filepath) {
    printf("Client: Avvio del client per il file '%s'.\n", filepath);

    // 1. Recupero della coda di messaggi del server
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666); // Ottieni la coda esistente
    if (server_msqid == -1) {
        perror("Client: Errore nel recupero della coda di messaggi del server. Assicurati che il server sia in esecuzione.");
        exit(1);
    }
    printf("Client: Coda di messaggi del server ottenuta con ID: %d\n", server_msqid);

    // 2. Recupero della memoria condivisa
    key_t shm_key = SHM_KEY;
    int shmid = shmget(shm_key, sizeof(SharedMemoryData), 0666); // Ottieni la memoria condivisa esistente
    if (shmid == -1) {
        perror("Client: Errore nel recupero della memoria condivisa. Assicurati che il server sia in esecuzione.");
        exit(1);
    }
    // Attaccamento della memoria condivisa
    SharedMemoryData *shm_ptr = (SharedMemoryData *)shmat(shmid, NULL, 0);
    if (shm_ptr == (void *)-1) {
        perror("Client: Errore nell'attaccamento alla memoria condivisa");
        exit(1);
    }
    printf("Client: Memoria condivisa attaccata con ID: %d\n", shmid);

    // 3. Creazione della coda di messaggi di risposta del client
    pid_t client_pid = getpid(); // Ottieni il PID del processo corrente
    key_t client_mq_key = client_pid; // Usa il PID come chiave unica per la coda di risposta
    int client_msqid = msgget(client_mq_key, IPC_CREAT | 0666); // Crea la coda di risposta
    if (client_msqid == -1) {
        perror("Client: Errore nella creazione della coda di messaggi del client");
        shmdt(shm_ptr); // Scollega la memoria condivisa prima di uscire
        exit(1);
    }
    printf("Client: Coda di messaggi del client creata con ID: %d (chiave: %d)\n", client_msqid, client_mq_key);

    // Leggi il contenuto del file e scrivilo nella memoria condivisa
    FILE *file = fopen(filepath, "rb"); // Apri il file in modalità binaria di lettura
    if (!file) {
        perror("Client: Errore nell'apertura del file");
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL); // Rimuovi la coda di risposta del client
        exit(1);
    }

    // Determina la dimensione del file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET); // Torna all'inizio del file

    // Verifica se il file è troppo grande per la memoria condivisa
    if (file_size > MAX_FILE_SIZE) {
        fprintf(stderr, "Client: Errore: Il file '%s' è troppo grande (%ld bytes). Il limite è %d bytes.\n", filepath, file_size, MAX_FILE_SIZE);
        fclose(file);
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }

    // Leggi il file nel buffer della memoria condivisa
    size_t bytes_read = fread(shm_ptr->data, 1, file_size, file);
    if (bytes_read != file_size) {
        fprintf(stderr, "Client: Errore nella lettura del file. Letti %zu bytes su %ld.\n", bytes_read, file_size);
        fclose(file);
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    shm_ptr->data_size = bytes_read; // Aggiorna la dimensione dei dati nella memoria condivisa
    fclose(file);
    printf("Client: File '%s' letto e scritto in memoria condivisa (%zu bytes).\n", filepath, shm_ptr->data_size);

    // Invia la richiesta al server
    struct RequestMessage request;
    request.mtype = 1; // Tipo di messaggio standard per la richiesta
    request.client_pid = client_pid; // Includi il PID del client
    strncpy(request.filename, filepath, sizeof(request.filename) - 1);
    request.filename[sizeof(request.filename) - 1] = '\0'; // Assicurati che sia null-terminato

    if (msgsnd(server_msqid, &request, sizeof(struct RequestMessage) - sizeof(long), 0) == -1) {
        perror("Client: Errore nell'invio della richiesta al server");
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    printf("Client: Richiesta inviata al server. In attesa di risposta...\n");

    // Ricevi la risposta dal server
    struct ResponseMessage response;
    // mtype = 1 per ricevere messaggi di tipo "risposta"
    if (msgrcv(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), 1, 0) == -1) {
        perror("Client: Errore nella ricezione della risposta dal server");
        shmdt(shm_ptr);
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }
    // Messaggio di conferma che la risposta è stata ricevuta
    printf("Client: Risposta dal server ricevuta.\n");

    printf("Client: SHA-256 ricevuto: %s\n", response.sha256_hash);

    // Pulizia delle risorse del client
    shmdt(shm_ptr); // Scollega la memoria condivisa
    msgctl(client_msqid, IPC_RMID, NULL); // Rimuovi la coda di messaggi di risposta del client
    printf("Client: Pulizia completata.\n");
}

// --- Funzione main ---

int main(int argc, char *argv[]) {
    // Verifica gli argomenti della riga di comando per determinare se avviare il server o il client
    if (argc < 2) {
        fprintf(stderr, "Utilizzo:\n");
        fprintf(stderr, "  Per avviare il server: %s server\n", argv[0]);
        fprintf(stderr, "  Per avviare il client: %s client <percorso_file>\n", argv[0]);
        exit(1);
    }

    // Se il primo argomento è "server", avvia la funzione del server
    if (strcmp(argv[1], "server") == 0) {
        run_server();
    }
    // Se il primo argomento è "client" e c'è un secondo argomento (il percorso del file), avvia la funzione del client
    else if (strcmp(argv[1], "client") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Utilizzo: %s client <percorso_file>\n", argv[0]);
            exit(1);
        }
        run_client(argv[2]);
    }
    // Se l'argomento non è riconosciuto, mostra l'utilizzo corretto
    else {
        fprintf(stderr, "Argomento non valido: '%s'\n", argv[1]);
        fprintf(stderr, "Utilizzo:\n");
        fprintf(stderr, "  Per avviare il server: %s server\n", argv[0]);
        fprintf(stderr, "  Per avviare il client: %s client <percorso_file>\n", argv[0]);
        exit(1);
    }

    return 0;
}
