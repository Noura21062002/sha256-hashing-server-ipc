#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h> // Per errno

// Costanti IPC
#define SERVER_MSG_QUEUE_KEY 1234
#define MAX_FILE_SIZE (256 * 1024) // Deve corrispondere al server

// Tipi di Messaggio (devono corrispondere al server)
#define MSG_TYPE_REQUEST 1
#define MSG_TYPE_CONTROL 2
#define MSG_TYPE_STATUS_REQ 3
#define MSG_TYPE_RESPONSE 4

// Struttura per messaggio di richiesta (client a server)
struct RequestMessage
{
    long mtype;
    pid_t client_pid;
    char filename[256];
    size_t file_size;
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

// --- Funzioni di Utilità Client ---

// Invia una richiesta di hashing al server
void send_hash_request(const char *filename)
{
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666); // Ottieni la coda del server
    if (server_msqid == -1)
    {
        perror("Client Hash: Errore nel recuperare la coda messaggi del server");
        exit(1);
    }
    printf("Client Hash: Coda messaggi del server ottenuta con ID: %d\n", server_msqid);

    // Crea una coda messaggi privata per ricevere la risposta
    key_t client_mq_key = getpid(); // La PID del client come chiave
    int client_msqid = msgget(client_mq_key, IPC_CREAT | 0666);
    if (client_msqid == -1)
    {
        perror("Client Hash: Errore nella creazione della coda messaggi del client");
        exit(1); // Esci se non riusciamo a creare la coda
    }
    printf("Client Hash: Coda messaggi del client creata con ID: %d (chiave: %d)\n", client_msqid, client_mq_key);

    // Leggi la dimensione del file
    struct stat st;
    if (stat(filename, &st) == -1)
    {
        perror("Client Hash: Errore nel recuperare le informazioni sul file");
        msgctl(client_msqid, IPC_RMID, NULL); // Pulisci la coda del client
        exit(1);
    }
    size_t file_size = st.st_size;

    if (file_size > MAX_FILE_SIZE) {
        fprintf(stderr, "Client Hash: Errore: Il file '%s' (dimensione %zu byte) supera il limite massimo del server (%d byte). Non invio la richiesta.\n",
                filename, file_size, MAX_FILE_SIZE);
        msgctl(client_msqid, IPC_RMID, NULL); // Pulisci la coda del client
        return; // Non esci, ma non invii la richiesta. Il client attenderà comunque una risposta.
    }


    struct RequestMessage request;
    request.mtype = MSG_TYPE_REQUEST;
    request.client_pid = getpid();
    strncpy(request.filename, filename, sizeof(request.filename) - 1);
    request.filename[sizeof(request.filename) - 1] = '\0';
    request.file_size = file_size;

    printf("Client Hash: Richiesta inviata al server. In attesa di risposta...\n");
    if (msgsnd(server_msqid, &request, sizeof(struct RequestMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Hash: Errore nell'invio della richiesta al server");
        msgctl(client_msqid, IPC_RMID, NULL); // Pulisci la coda del client
        exit(1);
    }

    // Attendi la risposta dal server
    struct ResponseMessage response;
    ssize_t bytes_received;
    do {
        bytes_received = msgrcv(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), MSG_TYPE_RESPONSE, 0);
    } while (bytes_received == -1 && errno == EINTR); // Gestisce interruzioni di sistema

    if (bytes_received == -1)
    {
        perror("Client Hash: Errore nella ricezione della risposta dal server");
    }
    else
    {
        printf("Client Hash: Hash ricevuto per '%s': %s\n", filename, response.content);
    }

    msgctl(client_msqid, IPC_RMID, NULL); // Rimuovi la coda messaggi del client
}

// Invia un messaggio di controllo al server per cambiare il limite worker
void send_control_message(int new_max_workers)
{
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Control: Errore nel recuperare la coda messaggi del server");
        exit(1);
    }

    struct ControlMessage control;
    control.mtype = MSG_TYPE_CONTROL;
    control.new_max_workers = new_max_workers;

    printf("Client Control: Invio messaggio per impostare limite worker a %d...\n", new_max_workers);
    if (msgsnd(server_msqid, &control, sizeof(struct ControlMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Control: Errore nell'invio del messaggio di controllo");
        exit(1);
    }
    printf("Client Control: Messaggio di controllo inviato.\n");
}

// Invia una richiesta di stato al server e stampa la risposta
void request_status()
{
    key_t server_mq_key = SERVER_MSG_QUEUE_KEY;
    int server_msqid = msgget(server_mq_key, 0666);
    if (server_msqid == -1)
    {
        perror("Client Status: Errore nel recuperare la coda messaggi del server");
        exit(1);
    }

    // Crea una coda messaggi privata per ricevere la risposta
    key_t client_mq_key = getpid();
    int client_msqid = msgget(client_mq_key, IPC_CREAT | 0666);
    if (client_msqid == -1)
    {
        perror("Client Status: Errore nella creazione della coda messaggi del client");
        exit(1);
    }

    struct StatusRequestMessage status_req;
    status_req.mtype = MSG_TYPE_STATUS_REQ;
    status_req.client_pid = getpid();

    printf("Client Status: Richiesta stato inviata al server. In attesa di risposta...\n");
    if (msgsnd(server_msqid, &status_req, sizeof(struct StatusRequestMessage) - sizeof(long), 0) == -1)
    {
        perror("Client Status: Errore nell'invio della richiesta di stato");
        msgctl(client_msqid, IPC_RMID, NULL);
        exit(1);
    }

    // Attendi la risposta dal server
    struct ResponseMessage response;
    ssize_t bytes_received;
    do {
        bytes_received = msgrcv(client_msqid, &response, sizeof(struct ResponseMessage) - sizeof(long), MSG_TYPE_RESPONSE, 0);
    } while (bytes_received == -1 && errno == EINTR);

    if (bytes_received == -1)
    {
        perror("Client Status: Errore nella ricezione della risposta di stato");
    }
    else
    {
        printf("Client Status: Risposta stato server: %s\n", response.content);
    }

    msgctl(client_msqid, IPC_RMID, NULL); // Rimuovi la coda messaggi del client
}

// --- Funzione Principale del Client ---

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Uso: %s <comando> [argomenti...]\n", argv[0]);
        fprintf(stderr, "Comandi:\n");
        fprintf(stderr, "  hash <percorso_file>\n");
        fprintf(stderr, "  control <nuovo_limite_worker>\n");
        fprintf(stderr, "  status\n");
        return 1;
    }

    // Aggiungi un piccolo ritardo per dare tempo al server di inizializzare
    // Questo è particolarmente utile quando i client vengono avviati in rapida successione.
    usleep(100000); // Ritardo di 100 millisecondi

    if (strcmp(argv[1], "hash") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Uso: %s hash <percorso_file>\n", argv[0]);
            return 1;
        }
        printf("Client Hash: Avvio per il file '%s'.\n", argv[2]);
        send_hash_request(argv[2]);
    }
    else if (strcmp(argv[1], "control") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Uso: %s control <nuovo_limite_worker>\n", argv[0]);
            return 1;
        }
        int new_limit = atoi(argv[2]);
        if (new_limit <= 0)
        {
            fprintf(stderr, "Errore: Il limite worker deve essere un numero positivo.\n");
            return 1;
        }
        send_control_message(new_limit);
    }
    else if (strcmp(argv[1], "status") == 0)
    {
        if (argc != 2)
        {
            fprintf(stderr, "Uso: %s status\n", argv[0]);
            return 1;
        }
        request_status();
    }
    else
    {
        fprintf(stderr, "Comando sconosciuto: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
