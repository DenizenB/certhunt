import requests
from os import environ as env

class UrlscanHelper:
    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            'API-Key': env['URLSCAN_KEY'],
        }

    def submit(self, url):
        data = {
            'url': url,
            'visibility': "public",
        }

        r = self.session.post(self.BASE_URL + "/scan", json=data)
        r.raise_for_status()

        return r.json()
