#!/usr/bin/env python3

# Standard library
from functools import cache
from os import environ as env

# External libraries
from pymisp import ExpandedPyMISP, MISPEvent, MISPTag, MISPAttribute


class MispHelper:
    def __init__(self, misp_url, misp_key, misp_verifycert):
        self.misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    def add_attribute(self, *, event_name: str, event_tags: list[str], parent_event_uuid: str = None, attr_type: str, attr_value: str, attr_comment: str, attr_category = "Network activity"):
        # Search for event, create it if it doesn't exist
        event = self._get_or_create_event(event_name, tuple(event_tags), parent_event_uuid)

        # Populate attribute
        attribute = MISPAttribute()
        attribute.category = attr_category
        attribute.type = attr_type
        attribute.value = attr_value
        attribute.comment = attr_comment

        # Send to backend
        result = self.misp.add_attribute(event, attribute)
        if 'errors' in result:
            raise Exception(f"Failed to add attribute: {result['errors']}")

    @cache
    def _get_or_create_event(self, name: str, tags: tuple[str], parent_event_uuid: str = None) -> MISPEvent:
        # Search for event
        results = self.misp.search(eventinfo=name, limit=1, metadata=True, pythonify=True)
        if results:
            return results[0]

        # Populate new event
        event = MISPEvent()
        event.info = name
        event.tags = [self._get_tag(tag_name) for tag_name in tags]
        if parent_event_uuid:
            event.extends_uuid = parent_event_uuid

        # Send to backend
        result = self.misp.add_event(event, metadata=True, pythonify=True)
        if 'errors' in result:
            raise Exception(f"Failed to create event: {result['errors']}")

        return result

    @cache
    def _get_tag(self, name: str) -> MISPTag:
        # Search for tag
        results = self.misp.search_tags(name, strict_tagname=True, pythonify=True)
        if not results:
            # Tag doesn't exist, log warning and move on
            print(f"Tag '{name}' does not exist")
            return MISPTag() # empty tags are ignored by the backend

        # Search is case-insensitive, i.e. can return [phishing, Phishing]
        # Try to match exact case
        for tag in results:
            if tag.name == name:
                return tag

        # Default to the first result, e.g. if wildcard search was used
        return results[0]

MispHelper.from_env = lambda: MispHelper(env['MISP_URL'], env['MISP_KEY'], env['MISP_VERIFYCERT'].lower() == "true")
