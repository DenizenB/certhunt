import logging
import requests
from os import environ as env

class UrlscanError(Exception):
    pass

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

        if r.status_code != 200:
            raise UrlscanError(data['message'])

        return data
