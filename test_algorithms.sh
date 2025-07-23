#!/bin/bash

# Definisci i percorsi di OpenSSL 3.0.15
OPENSSL_INCLUDE="/usr/local/openssl-3.0.15/include"
OPENSSL_LIB="/usr/local/openssl-3.0.15/lib64"
OPENSSL_RPATH="-Wl,-rpath=${OPENSSL_LIB}"

# --- Funzione per pulire le risorse IPC prima di ogni test ---
cleanup_ipc() {
    echo "Pulizia risorse IPC residue..."
    # Uccidi eventuali processi server precedenti
    pkill -f "./server"
    sleep 1 # Dai tempo al processo di terminare

    # Rimuovi code di messaggi e memoria condivisa (se esistono)
    # Usa ipcrm per rimuovere esplicitamente le risorse
    # SERVER_MSG_QUEUE_KEY 1234 (0x4d2 in esadecimale)
    ipcs -q | awk '/0x000004d2/ {print $2}' | xargs -r ipcrm -q
    # SHM_KEY 5678 (0x162e in esadecimale)
    ipcs -m | awk '/0x0000162e/ {print $2}' | xargs -r ipcrm -m

    # Rimuovi semafori nominati (potrebbero essere rimasti da un crash)
    # I semafori nominati sono file nel filesystem virtuale /dev/shm
    rm -f /dev/shm/sem.worker_limit_sem
    rm -f /dev/shm/sem.queue_mutex_sem
    rm -f /dev/shm/sem.queue_fill_sem
    rm -f /dev/shm/sem.shm_init_sem
    echo "Pulizia IPC completata."
}

# --- Compilazione dei programmi ---
echo "Compilazione del server e del client..."
# Compila il server con le librerie OpenSSL (-lssl -lcrypto) e POSIX semaphores (-lrt -pthread)
# Includi i percorsi personalizzati di OpenSSL
gcc server.c -o server -I"${OPENSSL_INCLUDE}" -L"${OPENSSL_LIB}" "${OPENSSL_RPATH}" -lrt -pthread -lssl -lcrypto
if [ $? -ne 0 ]; then
    echo "Errore durante la compilazione del server."
    exit 1
fi
# Compila il client con le librerie OpenSSL e POSIX semaphores
# Includi i percorsi personalizzati di OpenSSL
gcc client.c -o client -I"${OPENSSL_INCLUDE}" -L"${OPENSSL_LIB}" "${OPENSSL_RPATH}" -lrt -pthread -lssl -lcrypto
if [ $? -ne 0 ]; then
    echo "Errore durante la compilazione del client."
    exit 1
fi
echo "Compilazione completata."

# --- Generazione dei file di test ---
echo "Esecuzione dello script per la generazione dei file di test..."
./generate_test_files.sh
if [ $? -ne 0 ]; then
    echo "Errore durante la generazione dei file di test."
    exit 1
fi
echo "File di test pronti."

# --- Test FCFS (First-Come, First-Served) ---
echo -e "\n--- TEST ALGORITMO FCFS (First-Come, First-Served) ---"
cleanup_ipc # Pulizia prima del test FCFS

echo "Avvio del server in modalità FCFS con limite worker predefinito (5)..."
# Avvia il server in background e reindirizza l'output su un file di log
./server fcfs > server_fcfs.log 2>&1 &
SERVER_PID=$! # Cattura il PID del server
echo "Server avviato con PID: $SERVER_PID. Output reindirizzato a server_fcfs.log"
sleep 2 # Dai tempo al server di inizializzarsi

echo "Invio richieste client per FCFS (ordine di arrivo: grande, piccolo, medio) in rapida successione..."

# Invia richieste in rapida successione per osservare FCFS
./client hash test/large_file_1.bin & # Grande file, arriva per primo
PID1=$!
./client hash test/small_file_1.bin & # Piccolo file, arriva per secondo
PID2=$!
./client hash test/medium_file_1.bin & # Medio file, arriva per terzo
PID3=$!
./client hash test/large_file_2.bin & # Altro grande file
PID4=$!
./client hash test/small_file_2.bin & # Altro piccolo file
PID5=$!


echo "Tutte le richieste client FCFS inviate. In attesa del completamento..."
wait $PID1 $PID2 $PID3 $PID4 $PID5 # Attendi che tutti i client terminino

echo "Richiesta stato del server FCFS..."
./client status

echo "Terminazione del server FCFS..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null # Attendi che il server termini, ignora errori se già terminato
sleep 1 # Dai tempo al server di pulire

echo -e "\n--- VERIFICA FCFS ---"
echo "Controlla il file server_fcfs.log. Dovresti vedere i worker elaborare i file nell'ordine in cui sono stati ricevuti."
echo "Ad esempio, 'large_file_1' dovrebbe essere elaborato prima di 'small_file_1', anche se 'small_file_1' è più piccolo."
echo "Ultimi 20 righe di server_fcfs.log:"
tail -n 20 server_fcfs.log

# --- Test SJF (Shortest Job First) ---
echo -e "\n--- TEST ALGORITMO SJF (Shortest Job First) ---"
cleanup_ipc # Pulizia prima del test SJF

echo "Avvio del server in modalità SJF con limite worker predefinito (5)..."
# Avvia il server in background e reindirizza l'output su un file di log
./server sjf > server_sjf.log 2>&1 &
SERVER_PID=$! # Cattura il PID del server
echo "Server avviato con PID: $SERVER_PID. Output reindirizzato a server_sjf.log"
sleep 2 # Dai tempo al server di inizializzarsi

echo "Impostazione limite worker a 2 per SJF per forzare la coda..."
./client control 2
sleep 1 # Dai tempo al server di elaborare il messaggio di controllo

echo "Invio richieste client per SJF (stesso ordine di arrivo: grande, piccolo, medio) in rapida successione..."

# Invia le stesse richieste in rapida successione per riempire la coda
# I client vengono avviati in background e attesi alla fine per non bloccare l'invio.
./client hash test/large_file_1.bin & # Grande file
PID1=$!
./client hash test/small_file_1.bin & # Piccolo file
PID2=$!
./client hash test/medium_file_1.bin & # Medio file
PID3=$!
./client hash test/large_file_2.bin &
PID4=$!
./client hash test/small_file_2.bin &
PID5=$!

echo "Tutte le richieste client SJF inviate. In attesa del completamento..."
wait $PID1 $PID2 $PID3 $PID4 $PID5 # Attendi che tutti i client terminino

echo "Richiesta stato del server SJF..."
./client status

echo "Terminazione del server SJF..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null
sleep 1 # Dai tempo al server di pulire

echo -e "\n--- VERIFICA SJF ---"
echo "Controlla il file server_sjf.log. Dovresti vedere i worker elaborare prima i file più piccoli, indipendentemente dall'ordine di arrivo."
echo "Ad esempio, 'small_file_1' dovrebbe essere elaborato prima di 'large_file_1', anche se 'large_file_1' è arrivato prima."
echo "Cerca le righe 'Worker PID X: Elaborazione richiesta per file...' e confronta le dimensioni dei file e i PID dei worker."
echo "Ultimi 20 righe di server_sjf.log:"
tail -n 20 server_sjf.log

echo -e "\n--- Test completati ---"
echo "Per un'analisi dettagliata, esamina i file server_fcfs.log e server_sjf.log."
