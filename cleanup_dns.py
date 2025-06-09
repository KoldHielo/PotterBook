import json
import requests
import os

KEY = os.environ['CF_API_KEY']
EMAIL = os.environ['CF_EMAIL']
ZONE = os.environ['PBOOK_ZONE']
DOMAIN = os.environ['CERTBOT_DOMAIN']

URL = f'https://api.cloudflare.com/client/v4/zones/{ZONE}/dns_records'
HEADERS = {
    'X-Auth-Email': EMAIL,
    'X-Auth-Key': KEY
}

response = requests.get(URL, headers=HEADERS).json()

for i in response['result']:
    if i['name'] == f'_acme-challenge.{DOMAIN}':
        url = URL + f'/{i["id"]}'
        r = requests.delete(url, headers=HEADERS)
        print(r.json())
