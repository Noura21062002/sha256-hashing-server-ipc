#!/bin/bash

mkdir -p test

# Genera file piccoli (da 1KB a 10KB)
for i in $(seq 1 10); do
    head -c $((1024 * i)) </dev/urandom > test/small_file_$i.bin
done

# Genera file medi (da 60KB a 100KB)
for i in $(seq 1 5); do
    head -c $((50 * 1024 + 10 * 1024 * i)) </dev/urandom > test/medium_file_$i.bin
done

# Genera file grandi (da 210KB a 230KB, entro il limite di 256KB)
for i in $(seq 1 3); do
    head -c $((200 * 1024 + 10 * 1024 * i)) </dev/urandom > test/large_file_$i.bin
done

echo "File di test generati nella directory 'test/'."
ls -lh test/
