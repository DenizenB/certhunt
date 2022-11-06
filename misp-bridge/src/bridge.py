#!/usr/bin/env python3

# Standard library
import json
from functools import cache
from os import environ as env

# External libraries
import redis

# Project modules
from misp_helper import MispHelper

def main():
    misp = MispHelper.from_env()
    r = redis.Redis(host="redis", port=6379, db=1)

    # Subscribe to redis attribute channel
    print("Subscribing to 'attributes' channel...")
    channel = r.pubsub()
    channel.subscribe("attributes")

    while True:
        # Block until a message is received
        message = channel.get_message(ignore_subscribe_messages=True, timeout=None)
        if not message:
            continue

        result = json.loads(message['data'].decode())
        print("Received result:", attribute)

        # Create attribute
        misp.create_attribute()

if __name__ == "__main__":
    main()
