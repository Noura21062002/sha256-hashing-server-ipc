# Progetto Server SHA-256 con IPC

Questo progetto implementa un sistema client-server per il calcolo dell'hash SHA-256 di file multipli, sfruttando i meccanismi di comunicazione inter-processo (IPC) disponibili su Linux/macOS. Il sistema è pensato per essere robusto, scalabile e facilmente estendibile.

---

## Descrizione Generale

Il progetto è composto da due programmi principali:

- **Server:** Riceve richieste dai client, gestisce la comunicazione tramite IPC, coordina un pool di worker e restituisce il risultato dell'hash.
- **Client:** Permette di inviare file al server per il calcolo dell'hash, modificare il limite di worker e richiedere lo stato del server.

---

## Meccanismi di Comunicazione (IPC)

### 1. Code di Messaggi

Le code di messaggi POSIX vengono utilizzate per inviare richieste dal client al server e per ricevere le risposte. Ogni messaggio contiene informazioni come il tipo di richiesta, il nome del file, la dimensione e l'identificatore del client.

**Vantaggi:**

- Decoupling tra processi
- Possibilità di gestire più richieste contemporaneamente

### 2. Memoria Condivisa

Un buffer di memoria condivisa viene utilizzato per trasferire efficientemente i dati dei file tra client e server. Il client scrive il contenuto del file nel buffer, e il server lo legge per calcolare l'hash.

**Nota:**  
Nel progetto base è presente un solo buffer condiviso, quindi solo una richiesta può essere gestita alla volta. Per una vera elaborazione parallela, si dovrebbe implementare un pool di buffer.

### 3. Semafori Nominati

I semafori POSIX vengono usati per sincronizzare l'accesso alle risorse condivise:

- **worker_limit_sem:** Limita il numero di worker attivi.
- **queue_mutex_sem:** Protegge l'accesso alla coda delle richieste.
- **queue_fill_sem:** Segnala la presenza di nuove richieste.
- **shm_init_sem:** Sincronizza l'inizializzazione della memoria condivisa.

---

## Pool di Worker

Il server crea un pool di processi worker tramite `fork()`. Ogni worker si occupa di elaborare una richiesta (calcolo hash) in parallelo. Il numero massimo di worker attivi è configurabile e può essere modificato dinamicamente tramite il client di controllo.

**Vantaggi:**

- Maggiore throughput
- Gestione efficiente di richieste multiple

---

## Algoritmi di Schedulazione

Il server può essere avviato con due modalità di schedulazione:

- **FCFS (First-Come, First-Served):** Le richieste vengono elaborate nell'ordine di arrivo.
- **SJF (Shortest Job First):** Le richieste con file di dimensione minore hanno priorità.

Questo permette di ottimizzare il tempo di risposta in base alle esigenze.

---

## Funzionalità del Client

Il client supporta tre modalità operative:

1. **hash:** Invia un file al server per il calcolo dell'hash SHA-256.
2. **control:** Modifica il limite massimo di worker attivi sul server.
3. **status:** Richiede informazioni sullo stato attuale del server (numero di worker, richieste in coda, ecc.).

---

## Struttura del Progetto

- `server.c`: Codice sorgente del server.
- `client.c`: Codice sorgente del client.
- `readme.md`: Documentazione.

---

## Prerequisiti

- Compilatore C (es. `gcc`)
- Librerie di sviluppo OpenSSL (`libssl-dev`)
- Sistema Linux/macOS

---

## Compilazione

```sh
gcc server.c -o server -lssl -lcrypto
gcc client.c -o client -lssl -lcrypto
```

---

## Esecuzione

### 1. Avvio del Server

```sh
./server fcfs    # oppure ./server sjf
```

### 2. Utilizzo del Client

#### a) Calcolo Hash

```sh
./client hash test_file.txt
```

#### b) Modifica Limite Worker

```sh
./client control 2
```

#### c) Stato Server

```sh
./client status
```

---

## Note Tecniche

- **Gestione Errori:** Il server gestisce errori come `Interrupted system call` e ripristina lo stato.
- **Pulizia Risorse:** Alla chiusura, il server libera tutte le risorse IPC. In caso di crash, è possibile pulire manualmente con i comandi indicati.
- **Sicurezza:** L'accesso alle risorse condivise è protetto da semafori per evitare race condition.

---

## Pulizia Manuale delle Risorse IPC

```sh
ipcs -q      # Visualizza code di messaggi
ipcs -m      # Visualizza memoria condivisa
ls /dev/shm/ # Visualizza semafori POSIX

ipcrm -q <ID_CODA_MESSAGGI>
ipcrm -m <ID_MEMORIA_CONDIVISA>
rm /dev/shm/sem.worker_limit_sem
rm /dev/shm/sem.queue_mutex_sem
rm /dev/shm/sem.queue_fill_sem
rm /dev/shm/sem.shm_init_sem
```

---

## Possibili Estensioni

- Implementazione di un pool di buffer per vera elaborazione parallela.
- Supporto per autenticazione client-server.
- Logging avanzato delle richieste e delle risposte.
- Interfaccia grafica per la gestione del server.

---

## FAQ

**D: Cosa succede se invio più richieste contemporaneamente?**  
R: Con il buffer singolo, le richieste vengono gestite una alla volta. Con un pool di buffer, il server può gestire più richieste in parallelo.

**D: Come posso aumentare la sicurezza?**  
R: Si possono aggiungere controlli di autenticazione e cifratura dei dati.

---

Per ulteriori dettagli, consulta il codice sorgente e i commenti all'interno dei file `server.c` e
