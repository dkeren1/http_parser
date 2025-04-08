#!/bin/bash

URLS=("http://example.com" "http://example.org")

for i in {1..50}; do
    URL=${URLS[$((RANDOM % 2))]}

    curl -s "$URL" > /dev/null
    
    SLEEP_TIME=$((RANDOM % 5 + 1))
    echo "i: $i" "$SLEEP_TIME"   "$URL"
    sleep "$SLEEP_TIME"
done
