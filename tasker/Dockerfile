FROM python:3-alpine

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN apk update \
    && pip install -r requirements.txt --disable-pip-version-check \
    && rm requirements.txt

# Copy src into /app
COPY src .

# Run python
CMD ["python", "main.py"]
