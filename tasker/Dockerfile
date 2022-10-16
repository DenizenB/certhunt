FROM python:3-alpine

RUN mkdir /app && chown 405: /app
USER 405
ENV HOME=/app
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt --disable-pip-version-check \
    && rm requirements.txt

# Copy src into /app
COPY src .

# Run python
CMD ["python", "main.py"]
