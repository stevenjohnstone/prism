#!/bin/bash

window_width=$(tmux display-message -p '#{window_width}')
window_height=$(tmux display-message -p '#{window_height}')
window_zoomed_flag=$(tmux display-message -p '#{window_zoomed_flag}')

MIN_GRID_WIDTH=$((79*2 -1))
MIN_GRID_HEIGHT=$((24*2 -1))

if [[ ${window_width} -ge $MIN_GRID_WIDTH ]] && [[ ${window_height} -gt $MIN_GRID_HEIGHT ]] && [[ ${window_zoomed_flag} -eq 1 ]]; then 
    tmux resize-pane -Z
elif { [[ ${window_width} -lt $MIN_GRID_WIDTH ]] || [[ ${window_height} -lt $MIN_GRID_HEIGHT ]]; } && [[ ${window_zoomed_flag} -eq 0 ]]; then
    tmux select-pane -t .0
    tmux resize-pane -Z
fi
