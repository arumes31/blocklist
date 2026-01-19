FROM python:3.13-slim

# Set environment variables
ENV BLOCKED_RANGES="127.0.0.1/32,0.0.0.0/32,192.168.0.0/16,10.0.0.0/8,172.12.0.0/12"
ENV WEBHOOK2_ALLOWED_IPS="127.0.0.1,127.0.0.1"
ENV TZ="Europe/Vienna"

WORKDIR /app

# Upgrade pip and setuptools
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Core
RUN pip install --no-cache-dir Flask Werkzeug redis gunicorn gevent

# GeoIp
RUN pip install --no-cache-dir geoip2

# ToTp
RUN pip install --no-cache-dir pyotp

# Limiter
RUN pip install --no-cache-dir Flask-Limiter

# QR Code
RUN pip install --no-cache-dir qrcode[pil]

# Cleanup setuptools and wheel to remove vendored vulnerabilities
RUN pip uninstall -y setuptools wheel

COPY app.py /app

# Copy the .html file into the container
COPY dashboard.html /app/templates/dashboard.html
COPY login.html /app/templates/login.html
COPY whitelist.html /app/templates/whitelist.html
COPY admin_management.html /app/templates/admin_management.html

# Copy JS
COPY ./js/aether.js /app/static/js/aether.js
COPY ./js/simplex-noise.min.js /app/static/js/simplex-noise.min.js
COPY ./js/codepen-util.js /app/static/js/codepen-util.js

# Copy StaticContent
COPY ./cd/logo.png /app/static/cd/logo.png
COPY ./cd/favicon-color.png /app/static/cd/favicon-color.png

CMD ["gunicorn", "-k", "gevent", "-w", "4", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app:app"]