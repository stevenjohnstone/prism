#!/bin/bash

sed -r '/^Reading .* from /d; s/fuzz\.?[[:alpha:]]*|0x[0-9a-fA-F]*|==[[:digit:]]*==|T[[:digit:]]+|[[:digit:]]* bytes|[[:digit:]]*-byte//g' | head -"$SIGLINES" | xxh64sum - | cut -d' ' -f 1



