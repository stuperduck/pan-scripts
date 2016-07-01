#!/usr/bin/env python

import urllib2
import json
import sys


def merge_prefixes(payload):

    regions, services = {}, {}

    for prefix in payload['prefixes']:
        ip_prefix = prefix['ip_prefix']

        _regions = regions.setdefault(ip_prefix, [])
        _regions.append(prefix['region'])
        regions[ip_prefix] = _regions

        _services = services.setdefault(ip_prefix, [])
        _services.append(prefix['service'])
        services[ip_prefix] = _services

    merged = []

    for prefix in payload['prefixes']:
        ip_prefix = prefix['ip_prefix']
        prefix_tuple = (ip_prefix, regions[ip_prefix], services[ip_prefix])
        merged.append(prefix_tuple)

    return merged


def prefixes(includes=None, excludes=None, regions=None):

    f = file('out.txt', 'w')
    sys.stdout = f

    r = urllib2.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json')
    payload = json.load(r)

    if not includes:
        includes = []

    if not excludes:
        excludes = []

    if not regions:
        regions = []

    def valid_region(_regions):
        if not regions:
            return True

        for region in regions:
            if region in _regions:
                return True

    def valid_service(_services):
        for exclude in excludes:
            if exclude in _services:
                return False

        if not includes:
            return True

        for include in includes:
            if include in _services:
                return True

    filtered = []

    for ip_prefix, _regions, _services in merge_prefixes(payload):
        if valid_region(_regions):
            if valid_service(_services):
                filtered.append(ip_prefix)
                print ip_prefix

    return filtered
    f.close()

if __name__ == '__main__':

    #prefixes(includes=['AMAZON'], excludes=['EC2'], regions=['us-east-1'])
    prefixes(includes=['EC2'])
