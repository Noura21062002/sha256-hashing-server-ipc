#!/bin/bash

# Configuration
NUM_CONCURRENT_CLIENTS=10 # Number of clients to run concurrently

# --- IMPORTANT FIX: Make FILE_LIST an array ---
# Generate file list based on what 'generate_files.sh' creates
# Use find to get all generated .bin files and store them in an array
# We use 'mapfile' (or 'readarray') to read lines into an array.
mapfile -t FILE_LIST < <(find test/ -maxdepth 1 -name "*.bin" | sort)

# Check if any files were found
if [ ${#FILE_LIST[@]} -eq 0 ]; then
    echo "Error: No .bin files found in the 'test/' directory. Please run generate_files.sh first."
    exit 1
fi

echo "Found ${#FILE_LIST[@]} test files."
# For debugging, uncomment the next line to see the file list:
# printf '%s\n' "${FILE_LIST[@]}"

# Define the output directory
OUTPUT_DIR="output"

# Ensure the client executable exists
if [ ! -f "./client" ]; then
    echo "Error: Client executable not found. Please compile it first."
    exit 1
fi

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
echo "Client outputs will be saved in the '$OUTPUT_DIR/' directory."

echo "Launching $NUM_CONCURRENT_CLIENTS clients concurrently..."

START_TIME=$(date +%s.%N)

PIDS=()
for (( i=0; i<$NUM_CONCURRENT_CLIENTS; i++ )); do
    # Pick a file from the list, cycling through if more clients than available files
    FILE_TO_HASH="${FILE_LIST[$((i % ${#FILE_LIST[@]}))]}"
    
    # Generate a unique output file name for each client
    OUTPUT_FILE="${OUTPUT_DIR}/client_output_${i}_$(basename "$FILE_TO_HASH" .bin).txt"

    echo "Client $((i+1)): Hashing '$FILE_TO_HASH' (output to '$OUTPUT_FILE')"
    # Run the client in the background, redirecting stdout and stderr to the output file
    ./client hash "$FILE_TO_HASH" > "$OUTPUT_FILE" 2>&1 &
    PIDS+=($!) # Store PID of background process
    
    # Add a small delay to avoid too many clients starting at the exact same microsecond,
    # which can sometimes lead to very rapid message queue access.
    # Not strictly necessary but can make behavior slightly more realistic.
    sleep 0.05 # Increased sleep slightly for better separation in logs
done

echo "Waiting for all clients to finish..."

# Wait for all background clients to complete
for pid in "${PIDS[@]}"; do
    wait $pid
done

END_TIME=$(date +%s.%N)

DURATION=$(echo "$END_TIME - $START_TIME" | bc)
echo "All clients finished."
echo "Total execution time for $NUM_CONCURRENT_CLIENTS clients: ${DURATION} seconds."

echo "Individual client results are in the '$OUTPUT_DIR/' directory."