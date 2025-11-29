#!/bin/bash

head -10 | sed -r 's/fuzz\.?[[:alpha:]]*|0x[0-9a-fA-F]*|==[[:digit:]]*==|[[:digit:]]* bytes|[[:digit:]]*-byte//g' | xxh64sum - | cut -d' ' -f 1



