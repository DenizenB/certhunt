#!/usr/bin/env python
from redis import Redis

from urlscan import UrlscanHelper
from tweets import TwitterHelper

cache = Redis(host='redis')

class Job:
    def __init__(self, query):
        self.query = query

    def get_new(query):
        since_id = cache.get("id:" + query)

if __name__ == "__main__":
    runs = cache.incr('runs')
    cache.set('runs', runs)

    print(f"runs = {runs}")
