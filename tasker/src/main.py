#!/usr/bin/env python3
import logging

from job import UrlscanJob


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    jobs = [
        UrlscanJob("#phishing", tags=["#phishing"]),
        UrlscanJob("#gootloader", tags=["#gootloader"], referer="https://www.bing.com/"),
    ]

    for job in jobs:
        job.run()
