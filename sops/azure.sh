#!/usr/bin/env bash

az login \
    && export AZURE_CLIENT_ID="30d4352e-e699-4b37-975d-6e38d30a30f6"
        export AZURE_CLIENT_SECRET="f3Z8Q~.PdkQ1Mg-9ZMTRZFFdSBtBgx6y-uwscaGp"
        export AZURE_TENANT_ID="141d8fe2-bf63-4de7-8782-1e1b896f03c9"

clear

# MANDATORY *.JSON.
sops -e env.json > env.enc.dev2
    cat env.enc.dev2

tail -f /dev/null