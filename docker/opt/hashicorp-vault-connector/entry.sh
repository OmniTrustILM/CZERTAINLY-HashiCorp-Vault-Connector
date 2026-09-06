#!/bin/sh

home="/opt/hashicorp-vault-connector"
source ${home}/static-functions

log "INFO" "Launching the HashiCorp Vault Connector"
./appbin
