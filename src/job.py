import logging
import re
from redis import Redis
from datetime import timedelta

from urlscan import UrlscanHelper, UrlscanError
from tweets import Tweet, TwitterHelper
from indicator import Url


cache = Redis(host='redis')
twitter = TwitterHelper()

class Job:
    def __init__(self, twitter_query: str, retweets = False):
        self.twitter_query = twitter_query
        self.retweets = retweets
        self.last_id_key = "id:" + twitter_query

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
        tweets = list(twitter.search(query=self.twitter_query, retweets=self.retweets, since_id=self.last_id, limit=100))

        # Process tweets
        for tweet in tweets:
            if not self.filter(tweet):
                continue

            self.process(tweet)

        # Remember since_id
        if tweets:
            self.last_id = tweets[0].id

    def filter(self, tweet: Tweet):
        return True

    def process(self, tweet: Tweet):
        raise NotImplemented()

class UrlscanJob(Job):
    def __init__(self, twitter_query: str, retweets = False, backoff = timedelta(days=3), tags: list[str] = [], referer: str = ""):
        super().__init__(twitter_query, retweets)
        self.urlscan = UrlscanHelper()

        self.backoff = backoff
        self.tags = tags
        self.referer = referer

    def filter(self, tweet):
        return tweet.has_indicator(Url) or re.search(r"(?<!t\.co)/(?!t\.co)(?!/t\.co)", tweet.text)

    def process(self, tweet: Tweet):
        urls = tweet.get_indicators(Url)

        if not urls:
            logging.warning(f"May have failed to parse defanged URL in tweet {tweet.id}:\n\t" + tweet.text.replace("\n", "\n\t"))

        for url in urls:
            cache_key = "urlscan:" + url.url
            if cache.exists(cache_key):
                logging.info(f"{self.twitter_query} -> {tweet.id} -> {url.url} -> Already submitted")
                continue

            logging.info(f"{self.twitter_query} -> {tweet.id} -> {url.url} -> Submitting to urlscan")

            # Append author to tags
            tags = self.tags + [f"@{tweet.author}"]

            try:
                self.urlscan.submit(url.url, tags=tags, referer=self.referer)
            except UrlscanError as e:
                logging.error(f"Failed to scan: {e}")

            # Remember scan to avoid submitting duplicates until 'backoff' period has passed
            cache.set(cache_key, b"", ex=self.backoff)
