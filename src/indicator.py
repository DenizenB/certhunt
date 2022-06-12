import re
from dataclasses import dataclass, field
from typing import NamedTuple
from datetime import datetime
from urllib.parse import urlparse


class Indicator:
    pass

@dataclass(frozen=True)
class Ip(Indicator):
    ip: str

    def __repr__(self):
        return self.ip

@dataclass(frozen=True)
class IpPort(Indicator):
    ip: str
    port: int

    def __post_init__(self):
        super().__setattr__('port', int(self.port))

    def __repr__(self):
        return f"self.ip:self.port"

@dataclass(frozen=True)
class Hash(Indicator):
    hash: str

    def __repr__(self):
        return self.hash

@dataclass(frozen=True)
class Url(Indicator):
    url: str
    host: str = field(init=False)
    path: str = field(init=False)
    query: str = field(init=False)

    def __post_init__(self):
        url = urlparse(self.url)
        super().__setattr__('host', url.netloc)
        super().__setattr__('path', url.path)
        super().__setattr__('query', url.query)

    def __repr__(self):
        return self.url

def parser(cls, regex):
    return (cls, re.compile(regex))

class IocParser:
    defang_characters = re.compile(r"[\[\]]")
    defanged_scheme = re.compile(r"[htpxX]*(s?)://")

    parsers = [
        parser(Ip,      r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        parser(IpPort,  r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d{1,5})"),
        parser(Hash,    r"(?i)\b(?P<hash>[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b"),
        parser(Url,     r"(?P<url>https?://(?!t\.co/)[^\s\"]+)"),
        parser(Url,     r"(?m)(?:^|\s)s?/(?P<url>[^\s\"]+\.[^\s\"]+)"), # formats used by e.g. @illegalFawn, @dubstard
    ]

    def fang_text(self, text):
        fanged_text = self.defang_characters.sub("", text)
        fanged_text = self.defanged_scheme.sub(r"http\1://", fanged_text)
        return fanged_text

    def parse_indicators(self, text):
        results = set()
        fanged_text = self.fang_text(text)

        for cls, pattern in self.parsers:
            for match in pattern.finditer(fanged_text):
                indicator = cls(**match.groupdict())
                results.add(indicator)

        return results
