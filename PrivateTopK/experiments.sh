#!/bin/bash

# 1. Configuration Arrays
# TABLE_SIZES=(10 15 20 30)
TABLE_SIZES=(10 20 30 40)
STREAM_SIZES=(200)

# 2. Output Directory Setup
OUTPUT_DIR="output"
mkdir -p "$OUTPUT_DIR"

# 3. Compile Once
echo "Compiling release build..."
CC=gcc-12 CXX=g++-12 RUSTFLAGS="-C target-cpu=native" cargo build --release

if [ $? -ne 0 ]; then
    echo "Compilation failed! Exiting."
    exit 1
fi

# 4. Create Single Log File
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOGFILE="${OUTPUT_DIR}/experiment_suite_${TIMESTAMP}.log"

echo "Starting experiments..."
echo "All output will be saved to: $LOGFILE"
echo "--------------------------------"

# Initialize file with a header
echo "Experiment Suite Started: $TIMESTAMP" > "$LOGFILE"
echo "==========================================" >> "$LOGFILE"

# 5. Nested Loops
for TABLE in "${TABLE_SIZES[@]}"; do
    for STREAM in "${STREAM_SIZES[@]}"; do
        
        echo "Running: Table Size = $TABLE, Stream Size = $STREAM"
        
        # Write a header for this specific run into the file
        {
            echo ""
            echo "##################################################"
            echo "CONFIG: Table Size = $TABLE | Stream Size = $STREAM"
            echo "##################################################"
            echo ""
        } >> "$LOGFILE"

        # Run the binary and append (>>) both stdout and stderr to the logfile
        ./target/release/oblivious_spacesaving "$TABLE" "$STREAM" >> "$LOGFILE" 2>&1

    done
done

echo "--------------------------------"
echo "All experiments finished."
echo "Results stored in: $LOGFILE"