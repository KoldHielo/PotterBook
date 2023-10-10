command = '/home/ubuntu/webdev/venv/bin/gunicorn'
pythonpath = '/home/ubuntu/webdev/potterbook'
bind = '172.31.18.58:8001'
workers = 3
certfile='/etc/letsencrypt/live/potterbook.co-0001/fullchain.pem'
keyfile='/etc/letsencrypt/live/potterbook.co-0001/privkey.pem'
