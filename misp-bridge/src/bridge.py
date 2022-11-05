#!/usr/bin/env python3

# stdlib
import json
from os import environ as env

# ext lib
import redis
from pymisp import ExpandedPyMISP

def add_attribute(*, event_name: str, event_tags: list[str], parent_event: str, **attribute: dict):
    event_id = get_or_create_event(event_name, event_tags, parent_event)
    misp.add_attribute(attribute)

def get_or_create_event(name: str, tags: list[str]) -> int:
    event = misp.search(name, limit=1)



if __name__ == "__main__":
#    misp = ExpandedPyMISP(env['MISP_URL'], env['MISP_KEY'], env['MISP_VERIFYCERT'].lower() == "true")
    r = redis.Redis(host="redis", port=6379, db=1)

    print("Subscribing to 'attributes' channel...")

    # Subscribe to redis attribute channel
    channel = r.pubsub()
    channel.subscribe("attributes")
    while True:
        # Block until a message is received
        message = channel.get_message(ignore_subscribe_messages=True, timeout=None)
        if not message:
            continue

        print("Received message:", message)

        attribute = json.loads(message['data'].decode())
        print("Attribute:", attribute)
