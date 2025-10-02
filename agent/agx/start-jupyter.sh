#!/usr/bin/env bash
LOG=/tmp/jupyter.log
PORT=8889
NOTEBOOK_DIR="/mnt/vmstore/jupyternbks"

# ... (rest of the script is the same) ...

echo ">> Preparing to start JupyterLab with the following command:" >> "$LOG"
# The line below is the only change
echo "   nohup /opt/venv/bin/jupyter lab --ip=0.0.0.0 --port=$PORT --ServerApp.root_dir=\"$NOTEBOOK_DIR\" --allow-root --no-browser --ServerApp.token='' --ServerApp.password=''" >> "$LOG"

# Start JupyterLab using the full path
nohup /opt/venv/bin/jupyter lab \
  --ip=0.0.0.0 \
  --port=$PORT \
  --ServerApp.root_dir="$NOTEBOOK_DIR" \
  --ServerApp.port_retries=0 \
  --allow-root \
  --no-browser \
  --ServerApp.token='' \
  --ServerApp.password='' >> "$LOG" 2>&1 &

# ... (rest of the script is the same) ...

sleep 5

# Verify that the correct process has started
echo ">> Checking for running JupyterLab process with correct root directory..." >> "$LOG"
ps aux | grep "[j]upyter-lab" | grep -- "--ServerApp.root_dir=$NOTEBOOK_DIR" >> "$LOG"

if pgrep -f "jupyter-lab.*--ServerApp.root_dir=$NOTEBOOK_DIR" > /dev/null; then
  echo "SUCCESS: Jupyter Lab started correctly and is serving from $NOTEBOOK_DIR." >> "$LOG"
else
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >> "$LOG"
  echo "ERROR: The script-started Jupyter process was not found!" >> "$LOG"
  echo "This means another process (likely from the VS Code extension) took over." >> "$LOG"
  echo "Current Jupyter processes found:" >> "$LOG"
  ps aux | grep "[j]upyter" >> "$LOG"
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >> "$LOG"
fi

# Keep the container running with a shell
exec bash
