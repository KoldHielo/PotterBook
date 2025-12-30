#!/bin/bash
source /home/ubuntu/.bashrc
curl -s --request POST --url "https://api.cloudflare.com/client/v4/zones/${PBOOK_ZONE}/dns_records" --header 'Content-Type: application/json' --header "X-Auth-Email: $CF_EMAIL" --header "X-Auth-Key: $CF_API_KEY" --data '{"content": "'"${CERTBOT_VALIDATION}"'", "name": "_acme-challenge.'${CERTBOT_DOMAIN}'", "proxied": false, "type": "TXT", "ttl": 1}'
sleep 30
