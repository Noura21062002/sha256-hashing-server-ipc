#!/bin/bash

# Configurazione
NUM_CLIENT_CONCORRENTI=10

mapfile -t FILE_LIST < <(find test/ -maxdepth 1 -name "*.bin" | sort)

# Controlla la presenza di file .bin
if [ ${#FILE_LIST[@]} -eq 0 ]; then
    echo "Errore: Nessun file .bin trovato nella directory 'test/'. Esegui prima generate_files.sh."
    exit 1
fi

echo "Trovati ${#FILE_LIST[@]} file di test."

OUTPUT_DIR="output"

# Verifica la presenza dell'eseguibile client
if [ ! -f "./client" ]; then
    echo "Errore: Eseguibile 'client' non trovato. Compilalo prima di eseguire lo script."
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
echo "Gli output dei client saranno salvati nella directory '$OUTPUT_DIR/'."

echo "Avvio di $NUM_CLIENT_CONCORRENTI client in parallelo..."

START_TIME=$(date +%s.%N)

PIDS=()
for (( i=0; i<$NUM_CLIENT_CONCORRENTI; i++ )); do
    FILE_TO_HASH="${FILE_LIST[$((i % ${#FILE_LIST[@]}))]}"
    OUTPUT_FILE="${OUTPUT_DIR}/client_output_${i}_$(basename "$FILE_TO_HASH" .bin).txt"

    echo "Client $((i+1)): Hash del file '$FILE_TO_HASH' (output in '$OUTPUT_FILE')"
    
    ./client hash "$FILE_TO_HASH" > "$OUTPUT_FILE" 2>&1 &
    PIDS+=($!)
    
    sleep 0.05
done

echo "In attesa che tutti i client completino l'esecuzione..."

for pid in "${PIDS[@]}"; do
    wait $pid
done

END_TIME=$(date +%s.%N)

DURATA=$(echo "$END_TIME - $START_TIME" | bc)
echo "Tutti i client hanno terminato."
echo "Tempo totale di esecuzione per $NUM_CLIENT_CONCORRENTI client: ${DURATA} secondi."

echo "I risultati dei singoli client sono nella directory '$OUTPUT_DIR/'."
