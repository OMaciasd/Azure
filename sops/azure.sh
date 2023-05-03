#!/usr/bin/env bash

az login \
    && export AZURE_CLIENT_ID="A2uR3-(|13n7-1D"
        export AZURE_CLIENT_SECRET="A2uR3-(|13n7--53(R37"
        export AZURE_TENANT_ID="A2uR3--73n4N7-1D"

clear

# MANDATORY *.JSON.
sops -e env.json > env.enc.dev2
    cat env.enc.dev2

tail -f /dev/null
