#!/bin/bash

# Get the current session name
SESSION=$(tmux display-message -p '#S')
# List of common shells to identify "idle" panes
SHELLS_REGEX="^(bash|zsh|fish|sh|ksh|csh|dash)$"

echo "Sending Ctrl-C to all panes in session: $SESSION..."

# 1. Send Ctrl+C to all panes in the current session
# -s: target current session
# -F: format output (we just need the pane ID)
tmux list-panes -s -t "$SESSION" -F "#{pane_id}" | xargs -I {} tmux send-keys -t {} C-c

echo "Waiting for processes to exit..."

# 2. Wait loop
TIMEOUT=10 # Max wait time in seconds (optional safety net)
ELAPSED=0

while [ $ELAPSED -lt $TIMEOUT ]; do
  BUSY_PANES=0

  # Iterate over all panes to check if they are busy
  # format: pane_pid, pane_current_command
  while IFS=$' ' read -r pid cmd; do

    # Check if the command running is a shell
    if [[ "$cmd" =~ $SHELLS_REGEX ]]; then
      # It's a shell. Check if it has child processes (foreground jobs).
      # pgrep -P $pid returns child PIDs. If output is not empty, shell is busy.
      if pgrep -P "$pid" > /dev/null; then
        ((BUSY_PANES++))
      fi
    else
      # It's not a shell (e.g., vim, top running directly).
      # If the pane still exists with this command, it is busy.
      ((BUSY_PANES++))
    fi
  done < <(tmux list-panes -s -t "$SESSION" -F "#{pane_pid} #{pane_current_command}")

  if [ "$BUSY_PANES" -eq 0 ]; then
    echo "All panes are idle. Killing session."
    tmux kill-session -t "$SESSION"
    exit 0
  fi

  sleep 0.5
  ((ELAPSED++))
done

# 3. Force kill if timeout reached
echo "Timeout reached. Force killing session."
tmux kill-session -t "$SESSION"
