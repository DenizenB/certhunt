FROM python:3-alpine

# Alpine guest user
WORKDIR /app
RUN chown 405: /app
USER 405
ENV HOME=/app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt --disable-pip-version-check \
    && rm requirements.txt

# Copy src into /app
COPY src .

# Run python
CMD ["python", "main.py"]
