#!/usr/bin/python

"""
name: pan-export-config
description: Export config from Panorama
author: Steve Barber
company: Palo Alto Networks
prerequisites: python 2.7.5+ with the libraries listed in the 'import' statements.
last updated: 06/22/2016

Change log:
** 1.0 - created script

"""
try:
    import getpass
    import argparse
    import urllib
    import urllib2
    import ssl
    import httplib
    from xml.dom import minidom
except ImportError:
    raise ImportError("Verify the proper python modules are installed")


ssl._create_default_https_context = ssl._create_unverified_context

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="Name or IP address of the firewall/Panorama")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
parser.add_argument("-f", "--filename", default="export.xml", type=str, help="Export filename")
args = parser.parse_args()

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
if args.filename:
    fn = args.filename
else:
    fn = raw_input("Export to the following file: ")


def send_api_request(url, values):

    data = urllib.urlencode(values)
    request = urllib2.Request(url, data, )
    response = urllib2.urlopen(request).read()

    return minidom.parseString(response)


def get_api_key(hostname, username, password):

    url = 'https://' + hostname + '/api'
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

    if mode == "p":
        print ""
        print "Connection to Panorama detected..."
        testfile = urllib.URLopener()
        testfile.retrieve('https://' + ip + '/api/?type=export&category=configuration&key=' + key, fn)

    if mode == "f":
        print ""
        print "Connection to Firewall detected..."
        testfile = urllib.URLopener()
        testfile.retrieve('https://' + ip + '/api/?type=export&category=configuration&key=' + key, fn)

    print ""
    print "Script finished!"
    print ""


if __name__ == '__main__':
    main()
