#!/usr/bin/env python3
import logging
from datetime import timedelta
from asyncio import run, sleep

from job import UrlscanJob

JOB_INTERVAL = 60
JOBS = [
    UrlscanJob("#phishing", tags=["#phishing"]),
    UrlscanJob("#gootloader", tags=["#gootloader"], referer="https://www.bing.com/"),
]

async def main():
    while True:
        for job in JOBS:
            try:
                job.run()
            except:
                logging.exception(f"Failed to run job: {job.twitter_query}")

        await sleep(JOB_INTERVAL)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    run(main())
