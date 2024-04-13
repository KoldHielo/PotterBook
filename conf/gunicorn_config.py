command = '/home/ubuntu/webdev/venv/bin/gunicorn'
pythonpath = '/home/ubuntu/webdev/potterbook'
bind = '127.0.0.1:8001'
workers = 1
certfile='/etc/letsencrypt/live/potterbook.co/fullchain.pem'
keyfile='/etc/letsencrypt/live/potterbook.co/privkey.pem'
