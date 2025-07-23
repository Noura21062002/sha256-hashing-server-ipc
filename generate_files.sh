#!/bin/bash

mkdir -p test

# Generate small files (e.g., 1KB to 10KB)
for i in $(seq 1 10); do
    head -c $((1024 * i)) </dev/urandom > test/small_file_$i.bin
done

# Generate medium files (e.g., 50KB to 100KB)
for i in $(seq 1 5); do
    head -c $((50 * 1024 + 10 * 1024 * i)) </dev/urandom > test/medium_file_$i.bin
done

# Generate large files (e.g., 200KB to MAX_FILE_SIZE - 256KB is MAX_FILE_SIZE)
# Ensure these do not exceed MAX_FILE_SIZE (256 * 1024 bytes) as defined in your code
# If MAX_FILE_SIZE is 256KB, make sure your large files are slightly less to avoid "FILE_TOO_LARGE" errors.
# Let's target up to 250KB for safety.
for i in $(seq 1 3); do
    head -c $((200 * 1024 + 10 * 1024 * i)) </dev/urandom > test/large_file_$i.bin
done

echo "Generated test files in 'test/' directory."
ls -lh test/