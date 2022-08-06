import logging
import requests
from os import environ as env
from datetime import timedelta

class UrlscanError(Exception):
    pass

class RateLimitExceeded(UrlscanError):
    def __init__(self, message, reset_after_seconds):
        super().__init__(message)
        self.reset_after_seconds = reset_after_seconds

class UrlscanHelper:
    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            'API-Key': env['URLSCAN_KEY'],
        }

    def submit(self, url: str, tags: list[str] = [], referer: str = ""):
        data = {
            'url': url,
            'visibility': "public",
            'tags': tags,
            'referer': referer,
        }

        r = self.session.post(self.BASE_URL + "/scan", json=data)
        data = r.json()

        if r.status_code == 429:
            reset_after = 1 + int(r.headers['X-Rate-Limit-Reset-After'])
            raise RateLimitExceeded(data['message'], reset_after)

        if r.status_code != 200:
            raise UrlscanError(data['message'])

        return data
