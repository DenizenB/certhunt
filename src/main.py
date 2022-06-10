#!/usr/bin/env python3
import logging
from redis import Redis

from urlscan import UrlscanHelper
from tweets import TwitterHelper
from indicator import Url


cache = Redis(host='redis')
twitter = TwitterHelper()

class Job:
    def __init__(self, query):
        self.query = query
        self.last_id_key = "id:" + query

    @property
    def last_id(self):
        since_id = cache.get(self.last_id_key)
        since_id = None if since_id is None else since_id.decode()
        return since_id

    @last_id.setter
    def last_id(self, last_id):
        cache.set(self.last_id_key, last_id.encode())

    def run(self):
        # Search tweets
        tweets = list(twitter.search(query=self.query, since_id=self.last_id, limit=100))

        # Process tweets
        for tweet in tweets:
            if not self.filter(tweet):
                continue

            self.process(tweet)

        # Remember since_id
        if tweets:
            self.last_id = tweets[0].id

    def filter(self, tweet):
        return True

    def process(self, tweet):
        raise NotImplemented()

class UrlscanJob(Job):
    def __init__(self, query):
        super().__init__(query)
        self.urlscan = UrlscanHelper()

    def filter(self, tweet):
        return tweet.has_indicator(Url)

    def process(self, tweet):
        logging.info(f"Processing tweet {tweet.id}")
        urls = tweet.get_indicators(Url)
        for url in urls:
            if not url.path.strip("/"):
                logging.info("Skipping no path: " + url.url)
                continue

            cache_key = "urlscan:" + url.url
            if cache.exists(cache_key):
                logging.info("Skipping already scanned: " + url.url)
                continue

            logging.info("Submitting urlscan job: " + url.url)
            self.urlscan.submit(url.url)
            cache.set(cache_key, b"", ex=24*3600)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(funcName)s %(levelname)s %(message)s")

    jobs = [
        UrlscanJob("#phishing"),
        UrlscanJob("#gootloader"),
    ]

    for job in jobs:
        job.run()
