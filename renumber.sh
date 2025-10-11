# Set the actual script file name from the command-line argument ($1)
SCRIPT_FILE="$1" 

# awk ' ... rest of the awk code ... ' "$SCRIPT_FILE" > "$SCRIPT_FILE.new" && mv "$SCRIPT_FILE.new" "$SCRIPT_FILE"


awk '
    BEGIN { func_count = 0; }
    # Only renumber step_xx() function definitions, zero-padded
    /^[[:space:]]*step_xx\(\)[[:space:]]*\{/ {
        func_count++;
        pad = sprintf("%02d", func_count);
        sub(/step_xx/, "step_" pad);
    }
    # Track TOTAL_STEPS line
    /TOTAL_STEPS=/ { total_steps_line = NR; }
    { lines[NR] = $0 }
    END {
        if (total_steps_line) {
            gsub(/TOTAL_STEPS=[0-9]+/, "TOTAL_STEPS=" func_count, lines[total_steps_line]);
        }
        for (i=1; i<=NR; i++) {
            print lines[i];
        }
    }
' "$SCRIPT_FILE" > "$SCRIPT_FILE.new" && mv "$SCRIPT_FILE.new" "$SCRIPT_FILE"

echo "✅ Script steps and function names renumbered successfully. Total steps updated."