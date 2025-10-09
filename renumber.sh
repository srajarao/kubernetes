# Set the actual script file name from the command-line argument ($1)
SCRIPT_FILE="$1" 

# awk ' ... rest of the awk code ... ' "$SCRIPT_FILE" > "$SCRIPT_FILE.new" && mv "$SCRIPT_FILE.new" "$SCRIPT_FILE"

awk '
    # Initialize counter and array to store all lines
    BEGIN { step_count = 0; }
    
    # 1. Find and renumber the step definition comments
    /^#.*STEP [0-9]+:/ {
        step_count++;
        # Substitute the old number (e.g., STEP 27) with the new one (STEP 28)
        sub(/STEP [0-9]+/, "STEP " step_count);
    }
    
    # 2. Identify the line containing TOTAL_STEPS
    /TOTAL_STEPS=/ {
        total_steps_line = NR; # Store the line number
    }

    # Store every line (modified or not) in an array
    { lines[NR] = $0 }
    
    # END Block: Run after processing all lines
    END {
        # Update the TOTAL_STEPS line with the final count
        # The 'gsub' function is applied ONLY to the stored line where TOTAL_STEPS is defined.
        # It replaces the first number after 'TOTAL_STEPS=' with the final step_count.
        gsub(/TOTAL_STEPS=[0-9]+/, "TOTAL_STEPS=" step_count, lines[total_steps_line]);
        
        # Print all lines from the array, overwriting the original file
        for (i=1; i<=NR; i++) {
            print lines[i];
        }
    }
' "$SCRIPT_FILE" > "$SCRIPT_FILE.new" && mv "$SCRIPT_FILE.new" "$SCRIPT_FILE"

echo "✅ Script steps renumbered successfully. Total steps updated to the final count."