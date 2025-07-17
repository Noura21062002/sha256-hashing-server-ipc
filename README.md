
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
- `Makefile`: Script per compilare server e client.
- `README.md`: Documentazione.

---

## Prerequisiti

- Compilatore C (`gcc`)
- Librerie di sviluppo OpenSSL 3.0.15 installate in `/usr/local/openssl-3.0.15`
- Sistema Linux/macOS

---

## Compilazione con Makefile

Il progetto include un `Makefile` per compilare facilmente server e client con le corrette opzioni per OpenSSL 3.0.15.

Per compilare **sia server che client**:

```bash
make
```

Per compilare solo il server:

```bash
make server
```

Per compilare solo il client:

```bash
make client
```

Per pulire gli eseguibili compilati:

```bash
make clean
```

---

## Esecuzione

### 1. Avvio del Server

```bash
./server fcfs    # oppure ./server sjf
```

### 2. Utilizzo del Client

#### a) Calcolo Hash

```bash
./client hash nome_file
```

#### b) Modifica Limite Worker

```bash
./client control <numero_worker>
```

#### c) Stato Server

```bash
./client status
```

---

## Note Tecniche

- Il progetto usa OpenSSL 3.0.15, configurato manualmente con `-I` e `-L` nel Makefile.
- Il Makefile specifica il `rpath` per il corretto caricamento dinamico delle librerie OpenSSL.
- È necessario che la directory `/usr/local/openssl-3.0.15/lib64` contenga le librerie OpenSSL.

---

## Pulizia Manuale delle Risorse IPC

Se il server termina in modo anomalo, le risorse IPC potrebbero rimanere allocate. Per pulirle manualmente:

```bash
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

- Pool di buffer per vera elaborazione parallela.
- Autenticazione client-server.
- Logging avanzato.
- Interfaccia grafica di controllo.

---

## FAQ

**D: Posso inviare più richieste contemporaneamente?**  
R: Con un solo buffer condiviso, no. Serve un pool di buffer per la vera parallelizzazione.

**D: Come aumentare la sicurezza?**  
R: Aggiungendo autenticazione e cifratura.

---

Per dettagli consultare i sorgenti `server.c` e `client.c`.