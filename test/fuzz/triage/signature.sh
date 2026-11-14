#!/bin/bash
set -euo pipefail

: "${SIGLINES:=10}"

sed -E \
  -e '/^Reading [0-9]+ bytes from /d' \
  -e '/^Execution successful\.$/d' \
  -e '/\(rb_print_backtrace(\+0x[0-9a-fA-F]+)?\)/d' \
  -e '/diff_fatal_signal_handler/d' \
  -e '/__kernel_rt_sigreturn/d' \
  -e '/__restore_rt/d' \
  -e 's#^([^ :]+/)?fuzz(\.[A-Za-z0-9_.-]+)*:#fuzz_bin:#g' \
  -e 's#(/?[^ ("'\'']+/)?build/fuzz(\.[A-Za-z0-9_.-]+)*#fuzz_bin#g' \
  -e 's/ \[detail: .*\]$//' \
  -e 's/0x[0-9a-fA-F]+//g' \
  -e ':u' \
  -e 's/(: runtime error: .*[^A-Za-z0-9_])-?[0-9]+/\1/' \
  -e 't u' \
  -e 's/(READ|WRITE) of size [0-9]+/\1 of size N/g' \
  -e 's/==[0-9]+==//g' \
  -e 's/T[0-9]+//g' \
  -e 's/[0-9]+ byte\(s\)//g' \
  -e 's/[0-9]+ object\(s\)//g' \
  -e 's/[0-9]+ bytes//g' \
  -e 's/[0-9]+-byte//g' \
  | awk -v n="$SIGLINES" '
      /^INVARIANT\[/ && !inv { inv = $0 }
      !inv && NR <= n { lines[++c] = $0 }
      END {
        if (inv) {
          print inv
        } else {
          for (i = 1; i <= c; i++) print lines[i]
        }
      }
    ' | xxh64sum - | cut -d' ' -f 1
