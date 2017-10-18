#!/usr/bin/python

"""
name: pan-keygen
description: Get API Key for a specific user
author: Steve Barber
company: Palo Alto Networks
prerequisites: python 2.7.5+ with the libraries listed in the 'import' statements.
last updated: 07/22/2016

Change log:
** 1.0 - created script

"""
try:
    import getpass
    import argparse
    import string
    import urllib
    import urllib2
    import ssl
    import httplib
    import os.path
    from xml.dom import minidom
    from random import *
    from lxml import etree
    import xml.etree.ElementTree as ET
except ImportError:
    raise ImportError("Verify the proper python modules are installed")


ssl._create_default_https_context = ssl._create_unverified_context

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="Name or IP address of the firewall/Panorama")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
args = parser.parse_args()

print '\n'

try:
    if args.ip:
        ip = args.ip
    else:
        ip = raw_input("Enter the name or IP of the firewall/Panorama: ")
    if args.username:
        user = args.username
    else:
        user = raw_input("Enter the user login: ")
    if args.password:
        pw = args.password
    else:
        pw = getpass.getpass()

except KeyboardInterrupt:
    print '\n'
    print "Keyboard interrupt.  Exiting script."
    try:
        exit()
    except SystemExit:
        os._exit()


def send_api_request(url, values):

    context = ssl._create_unverified_context()

    data = urllib.urlencode(values)
    request = urllib2.Request(url, data, )
    conn = urllib2.urlopen(request, context=context)
    response = conn.read()
    conn.close()

    return minidom.parseString(response)


def get_api_key(ip, username, password):

    url = 'https://' + ip + '/api'
    values = {'type': 'keygen', 'user': username, 'password': password}
    parsedKey = send_api_request(url, values)
    nodes = parsedKey.getElementsByTagName('key')
    key = nodes[0].firstChild.nodeValue
    return key


def get_sys_info(ip, key):

    url = 'https://' + ip + '/api'
    values = {'type': 'op', 'cmd': '<show><system><info></info></system></show>', 'key': key}
    parsedKey = send_api_request(url, values)
    hostname = parsedKey.getElementsByTagName('hostname')
    serial = parsedKey.getElementsByTagName('serial')
    model = parsedKey.getElementsByTagName('model')
    version = parsedKey.getElementsByTagName('sw-version')

    try:
        if model[0].firstChild.nodeValue not in ('Panorama', 'M-100', 'M-500'):
            mode = "f"
            print "Getting firewall sysinfo..."
        else:
            mode = "p"
            print "Getting Panorama sysinfo..."

        print " "
        print "System Info"
        print "---------------------------------------"
        print "Hostname: " + hostname[0].firstChild.nodeValue
        print "Serial: " + serial[0].firstChild.nodeValue
        print "Model: " + model[0].firstChild.nodeValue
        print "Software: " + version[0].firstChild.nodeValue
        print "---------------------------------------"
        print " "

        return hostname[0].firstChild.nodeValue, mode
    except:
        print("Unable to get system information.  Check credentials and try again")


def main():

    key = get_api_key(ip, user, pw)
    hostname, mode = get_sys_info(ip, key)
    print ""
    print ""
    print "API key for user '" + user + "' = " + key

    print ""
    print "Script finished!"
    print ""


if __name__ == '__main__':
    main()
