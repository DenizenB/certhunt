import logging
from redis import Redis

from urlscan import UrlscanHelper, UrlscanError
from tweets import Tweet, TwitterHelper
from indicator import Url


cache = Redis(host='redis')
twitter = TwitterHelper()

class Job:
    def __init__(self, twitter_query: str):
        self.twitter_query = twitter_query
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
        tweets = list(twitter.search(query=self.twitter_query, since_id=self.last_id, limit=100))

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
    def __init__(self, twitter_query: str, tags: list[str], **urlscan_args):
        super().__init__(twitter_query)
        self.urlscan = UrlscanHelper()

        self.tags = tags
        self.urlscan_args = urlscan_args

    def filter(self, tweet):
        return tweet.has_indicator(Url)

    def process(self, tweet: Tweet):
        urls = tweet.get_indicators(Url)
        for url in urls:
            cache_key = "urlscan:" + url.url
            if cache.exists(cache_key):
                logging.info(f"{self.twitter_query} -> {tweet.id} -> {url.url} -> Already submitted")
                continue

            logging.info(f"{self.twitter_query} -> {tweet.id} -> {url.url} -> Submitting to urlscan")

            # Append author to tags
            tags = self.tags + [f"@{tweet.author}"]

            try:
                self.urlscan.submit(url.url, tags=tags, **self.urlscan_args)
            except UrlscanError as e:
                logging.error(f"Failed to scan: {e}")

            # Mark url as scanned for 24h to avoid submitting duplicates
            cache.set(cache_key, b"", ex=24*3600)
