#!/usr/bin/env python3

# Standard library
import json
import time

# External libraries
import redis

# Project modules
from misp_helper import MispHelper


def main():
    misp = MispHelper.from_env()
    r = redis.Redis(host="redis", port=6379, db=1)

    # Subscribe to redis channels
    channels = ['certhunt:attributes']
    print(f"Subscribing to: {channels}")

    channel = r.pubsub()
    channel.subscribe(*channels)

    while True:
        # Block until a message is received
        message = channel.get_message(ignore_subscribe_messages=True, timeout=None)
        if not message:
            continue

        try:
            attribute = json.loads(message['data'].decode())
            print("Received attribute\n", attribute)

            # Add attribute to MISP
            misp.add_attribute(**attribute)
        except Exception as e:
            print(f"Caught exception while adding attribute: {e}")

        # Backoff for 1 sec
        time.sleep(1)

if __name__ == "__main__":
    main()
