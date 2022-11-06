FROM python:3-alpine

WORKDIR /app

# Alpine guest user
RUN chown 405: /app
USER 405
ENV HOME=/app

COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir --disable-pip-version-check --no-warn-script-location \
    && rm requirements.txt

COPY src/ .

CMD ["python", "-u", "bridge.py"]
