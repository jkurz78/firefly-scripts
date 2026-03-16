#!/bin/sh
# Load the Enable Banking private key from file into the env var the app actually reads
if [ -f "/secrets/eb_private.key" ]; then
    export ENABLE_BANKING_PRIVATE_KEY=$(cat /secrets/eb_private.key)
    echo "[entrypoint] Enable Banking private key loaded (${#ENABLE_BANKING_PRIVATE_KEY} chars)"
else
    echo "[entrypoint] WARNING: /secrets/eb_private.key not found"
fi

# Hand off to the original importer entrypoint with the original CMD
exec /usr/local/bin/docker-php-serversideup-entrypoint /init
