#!/usr/bin/env python

import urllib2
import json
import sys


def merge_prefixes(payload):
    """
    Converts the AWS services JSON payload into a PAN external dynamic list compatible format.

    Arguments:

        payload => JSON object

    Returns:

        A list of tuples formatted as (ip_prefix, regions, services)

        ip_prefix => CIDR prefix
        regions   => list of all regions the prefix is associated with
        services  => list all services the prefix is associated with
    """

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
    """
    Filters the AWS services JSON payload by regions and/or services.

    Arguments:

        includes => list of services to allow
        excludes => list of services to disallow
        regions  => list of regions to allow

    Returns:

        A list of prefixes
    """

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
    # Lets get all the IPs associated with AMAZON services in us-east-1 that
    # are NOT used for EC2 instances
    #print(prefixes(includes=['AMAZON'], excludes=['EC2'], regions=['us-east-1']))
    #print(prefixes(includes=['AMAZON']))
    #prefixes(includes=['AMAZON'])
    prefixes(includes=['EC2'])