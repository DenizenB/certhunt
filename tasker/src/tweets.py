#!/usr/bin/env python3
import logging
from os import environ as env
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from typing import TypeVar

from tweepy import AppAuthHandler, API, Cursor

from indicator import *

@dataclass
class Tweet:
    id: str
    author: str
    created_at: datetime
    text: str
    indicators: list[Indicator]

    def get_indicators(self, indicator_type: TypeVar):
        return [indicator for indicator in self.indicators if type(indicator) == indicator_type]

    def has_indicator(self, indicator_type: TypeVar):
        return any([type(indicator) == indicator_type for indicator in self.indicators])

class TweetTranslator:
    def translate(self, tweet: Tweet, indicators: list[Indicator]):
        raise NotImplemented()

class TweetToDict(TweetTranslator):
    def translate(self, tweet, indicators):
        # Group indicators by type
        indicators_by_type = defaultdict(list)
        for indicator in indicators:
            key = type(indicator).__name__
            indicators_by_type[key].append(str(indicator))

        return {
            'id': tweet.id_str,
            'author': tweet.user._json['screen_name'],
            'created_at': tweet.created_at.isoformat(" ", "seconds"),
            'text': tweet.full_text,
            'indicators': indicators_by_type,
        }

class TweetToJson(TweetToDict):
    def translate(self, tweet, indicators):
        tweet = super().translate(tweet, indicators)
        return json.dumps(tweet)

class TweetToClass(TweetTranslator):
    def translate(self, tweet, indicators):
        return Tweet(
            id=tweet.id_str,
            author=tweet.user._json['screen_name'],
            created_at=tweet.created_at,
            text=tweet.full_text,
            indicators=indicators,
        )


class TwitterHelper:
    def __init__(self, translator: TweetTranslator = TweetToClass()):
        self.translator = translator
        self.parser = IocParser()

        auth = AppAuthHandler(env['TWITTER_KEY'], env['TWITTER_SECRET'])
        self.api = API(auth)

    def search(self, *, query: str, limit = 10, retweets = False, **search_args) -> list[Tweet]:
        results = 0

        cursor = Cursor(self.api.search_tweets, q=query, result_type='recent', tweet_mode='extended', **search_args)
        for tweet in cursor.items():
            if not retweets and 'retweeted_status' in tweet._json:
                continue

            indicators = self.parser.parse_indicators(tweet.full_text)
            yield self.translator.translate(tweet, indicators)

            results += 1
            if results >= limit:
                break

        logging.info(f"{query} -> {results} tweets")


if __name__ == "__main__":
    import argparse
    import json
    from sys import argv, stderr, exit

    logging.basicConfig(level=logging.DEBUG, stream=stderr)

    parser = argparse.ArgumentParser(description="Retrieve tweets (newest first) and any contained IOCs, output as json", add_help=False)
    parser.add_argument("query", type=str)
    parser.add_argument("--limit", type=int, default=10, help="Max number of tweets to return (default: 10)")
    parser.add_argument("--since-id", type=int, default=None, help="Fetch tweets newer than this tweet ID")
    parser.add_argument("--retweets", action='store_true', default=False, help="Include retweets in results")

    if len(argv) == 1:
        parser.print_help(stderr)
        exit(1)

    args = parser.parse_args()

    twitter = TwitterHelper(translator=TweetToJson())
    tweets = twitter.search(**args.__dict__)

    for tweet in tweets:
        print(tweet)
