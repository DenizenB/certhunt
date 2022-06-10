FROM python:3-alpine

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN apk update \
    && pip install -r requirements.txt --disable-pip-version-check \
    && rm requirements.txt

# Set up crontab
COPY crontab .
RUN crontab crontab \
    && rm crontab

# Copy src into /app
COPY src .

# Run cron
CMD ["crond", "-f"]
#CMD ["python", "main.py"]
