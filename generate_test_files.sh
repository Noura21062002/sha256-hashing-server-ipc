#!/bin/bash

# Crea la directory 'test' se non esiste
mkdir -p test

echo "Generazione file di test nella directory 'test/'..."

# Genera file piccoli (da 1KB a 10KB)
for i in $(seq 1 10); do
    # head -c N bytes from /dev/urandom creerà un file di N byte casuali
    head -c $((1024 * i)) </dev/urandom > test/small_file_$i.bin
    echo "  Creato test/small_file_$i.bin ($(du -h test/small_file_$i.bin | awk '{print $1}'))"
done

# Genera file medi (da 60KB a 100KB)
for i in $(seq 1 5); do
    head -c $((50 * 1024 + 10 * 1024 * i)) </dev/urandom > test/medium_file_$i.bin
    echo "  Creato test/medium_file_$i.bin ($(du -h test/medium_file_$i.bin | awk '{print $1}'))"
done

# Genera file grandi (da 210KB a 230KB, entro il limite di 256KB)
for i in $(seq 1 3); do
    head -c $((200 * 1024 + 10 * 1024 * i)) </dev/urandom > test/large_file_$i.bin
    echo "  Creato test/large_file_$i.bin ($(du -h test/large_file_$i.bin | awk '{print $1}'))"
done

echo "Tutti i file di test sono stati generati."
echo "Contenuto della directory 'test/':"
ls -lh test/