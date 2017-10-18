#!/usr/bin/python

"""
name: pan-gp-set-passcode
description: Set GlobalProtect Portal Agent Config Client Disable Passcode
author: Steve Barber
company: Palo Alto Networks
prerequisites: python 2.7.5+ with the libraries listed in the 'import' statements.
last updated: 10/16/2017

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
parser.add_argument("-f", "--filename", type=str, help="Export filename")
parser.add_argument("-P", "--portal", type=str, help="GlobalProtect portal name")
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
    if args.portal:
        portal = args.portal
    else:
        # portal = raw_input("Enter name of GP Portal: ")
        portal = "GP_Portal_Int"
    agent_config = "GP_Int_Agent_Config"

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


def gen_passcode():

    characters = string.ascii_letters + string.digits + ""
    passcode = "".join(choice(characters) for x in range(randint(16, 16)))
    print passcode
    return passcode


def write_passcode(passcode):

    file_object = open("passcode.txt", "w")
    file_object.write(passcode)
    file_object.close()


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


def set_passcode(ip, key, passcode):

    # urlencoded = urllib.quote_plus(passcode)
    setsuccess = False
    commitsuccess = False
    setstatus = ""
    conn = httplib.HTTPSConnection(ip, context=ssl._create_unverified_context())
    request_str = "/api/?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/" \
                  "entry[@name='vsys1']/global-protect/global-protect-portal/entry[@name='" + portal + "']/" \
                  "client-config/configs/entry[@name='" + agent_config + "']/agent-ui/passcode&element=<passcode>" \
                  + passcode + "</passcode>&key="
    conn.request("GET", request_str + key)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    r.close()
    setroot = etree.fromstring(data)
    # print etree.tostring(setroot)

    for x in setroot.iter():
        if x.tag == "response":
            if x.attrib["status"] == "success":
                setsuccess = True
                print "Passcode was set successfully!"
            else:
                print "Passcode failed to be changed.  Check that the portal and agent config are set correctly and " \
                        "try again."

    if setsuccess == True:
        conn = httplib.HTTPSConnection(ip, context=ssl._create_unverified_context())
        request_str = "/api/?type=commit&cmd=<commit></commit>&key="
        conn.request("GET", request_str + key)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        r.close()

        commitroot = etree.fromstring(data)
        #print etree.tostring(commitroot)

        for x in commitroot.iter():
            if x.tag == "response":
                if x.attrib["status"] == "success":
                    commitsuccess = True
                    print "Successfully issued commit on firewall!"
                else:
                    print "Failed to issue commit on firewall.  Check the firewall system log for more details."


def main():

    key = get_api_key(ip, user, pw)
    passcode = gen_passcode()
    passfile = write_passcode(passcode)
    print ""
    print ""
    print "API key for user '" + user + "' = " + key

    hostname, mode = get_sys_info(ip, key)
    result = set_passcode(ip, key, passcode)

    print ""
    print "Script finished!"
    print ""


if __name__ == '__main__':
    main()
