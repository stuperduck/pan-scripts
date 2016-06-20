#!/usr/bin/python

"""
name: pan_create_objects
description: Bulk create address objects and rules in Panorama or firewall
author: Steve Barber
company: Palo Alto Networks
prerequisites: python 2.7.5+ with the libraries listed in the 'import' statements.
last updated: 06/20/2016

Change log:
** 1.0 - created script

"""
import getpass
import argparse
import urllib
import urllib2
import ssl
import sys
import httplib
import ipaddress
from lxml import etree
from xml.dom import minidom

ssl._create_default_https_context = ssl._create_unverified_context

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="Name or IP address of the firewall/Panorama")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
parser.add_argument("-k", "--key", help="API Key")
parser.add_argument("-x", "--xpath", help="x-path")
parser.add_argument("-e", "--element", help="Element")
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


def send_api_request(url, values):

    data = urllib.urlencode(values)
    request = urllib2.Request(url, data, )
    response = urllib2.urlopen(request).read()

    return minidom.parseString(response)


def get_rule_names(url, values):
    data = urllib.urlencode(values)
    request = urllib2.Request(url, data, )
    response = urllib2.urlopen(request).read()
    for item in response.split("\n"):
        if "entry name=" in item:
            print item.split(' ', 1)
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


def query_yes_no(question, default="yes"):
        """Ask a yes/no question via raw_input() and return their answer.

        "question" is a string that is presented to the user.
        "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

        The "answer" return value is True for "yes" or False for "no".
        """
        valid = {"yes": True, "y": True, "ye": True,
                 "no": False, "n": False}
        if default is None:
            prompt = " [y/n] "
        elif default == "yes":
            prompt = " [Y/n] "
        elif default == "no":
            prompt = " [y/N] "
        else:
            raise ValueError("invalid default answer: '%s'" % default)

        while True:
            sys.stdout.write(question + prompt)
            choice = raw_input().lower()
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' "
                                 "(or 'y' or 'n').\n")


def main():

    key = get_api_key(ip, user, pw)
    hostname, mode = get_sys_info(ip, key)

    url = 'https://' + ip + '/api'

    if mode == "p":
        print ""
        print "Connection to Panorama detected..."

        dg = []

        addr_object_select = query_yes_no("Would you like to add address objects?")

        if addr_object_select:

            dev_group_select = query_yes_no("Would you like to add these objects to a device group?")

            if dev_group_select:
                """Panorama: Get device-groups."""
                conn = httplib.HTTPSConnection(ip, context=ssl._create_unverified_context())
                request_str = "/api/?type=op&cmd=<show><devicegroups><%2Fdevicegroups><%2Fshow>&key="
                conn.request("GET", request_str + key)
                r = conn.getresponse()
                data = r.read()
                p_dg = etree.fromstring(data)
                conn.close()
                r.close()

                for x in p_dg.findall("result/devicegroups/entry"):
                    dg.append(x.attrib['name'])

                for y in dg:
                    print y

                selected = raw_input("Which Device Group would you like to add objects too?" + "\n" + "\n".join(
                    [str(a+1) + ":" + b for a, b in enumerate(dg)]) + "\n" + "select from the list above...-> ")

                print ""
                print "Adding objects to " + dg[int(selected)-1]
                print ""
                xpathAddr = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + \
                            dg[int(selected)-1] + "']/address"
                xpathRule = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + \
                            dg[int(selected) - 1] + "']/pre-rulebase/security/rules"
            else:
                shared_select = query_yes_no("Would you like to add these objects as 'Shared'?")
                if shared_select:
                    xpathAddr = "/config/shared/address"
                else:
                    sys.exit()

            rule_create_select = query_yes_no("Would you like to add associated rules?")
            if rule_create_select:
                a_addr = raw_input("Enter base name for source address: ")
                a_subnet = unicode(raw_input("Enter subnet in CIDR for the SRC addresses (e.g. '10.1.0.0/16'): "))
                b_addr = raw_input("Enter base name for destination address: ")
                b_subnet = unicode(raw_input("Enter subnet in CIDR for the DST addresses (e.g. '20.1.0.0/16'): "))
                addr_count = raw_input("How many addresses would you like to create? ")

                for x in range(int(addr_count)):
                    a_addr_name = a_addr + "-" + str(x + 1)
                    b_addr_name = b_addr + "-" + str(x + 1)
                    a_subnet = ipaddress.ip_network(a_subnet)
                    b_subnet = ipaddress.ip_network(b_subnet)
                    a_address = a_subnet[x + 1]
                    b_address = b_subnet[x + 1]

                    elementA = '<entry name="' + a_addr_name + '"><ip-netmask>' + str(a_address) + \
                               '</ip-netmask></entry>'
                    elementB = '<entry name="' + b_addr_name + '"><ip-netmask>' + str(b_address) + \
                               '</ip-netmask></entry>'
                    valuesA = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathAddr, 'element': elementA}
                    valuesB = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathAddr, 'element': elementB}

                    send_api_request(url, valuesA)
                    send_api_request(url, valuesB)

                    elementRule = '<entry name="' + a_addr_name + '-' + b_addr_name + '"><to><member>Untrust</member>' \
                                  '</to><from><member>Trust</member></from><source><member>' + a_addr_name + \
                                  '</member></source><destination><member>' + b_addr_name + '</member></destination>' \
                                  '<source-user><member>any</member></source-user><category><member>any</member>' \
                                  '</category><application><member>any</member></application><service>' \
                                  '<member>application-default</member></service><hip-profiles><member>any</member>' \
                                  '</hip-profiles><action>allow</action></entry>'
                    valuesRule = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathRule, 'element': elementRule}

                    send_api_request(url, valuesRule)
            else:
                a_addr = raw_input("Enter base name for new addresses: ")
                a_subnet = unicode(raw_input("Enter subnet in CIDR for the new addresses (e.g. '10.1.0.0/16'): "))
                addr_count = int(raw_input("How many addresses would you like to create? "))

                for x in range(int(addr_count)):
                    addr_name = a_addr + "-" + str(x+1)
                    subnet = ipaddress.ip_network(a_subnet)
                    address = subnet[x + 1]

                    elementA = '<entry name="' + addr_name + '"><ip-netmask>' + str(address) + '</ip-netmask></entry>'
                    valuesA = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathAddr, 'element': elementA}

                    send_api_request(url, valuesA)

    if mode == "f":
        print ""
        print "Connection to Firewall detected..."

        addr_object_select = query_yes_no("Would you like to add address objects?")

        if addr_object_select:

            xpathAddr = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
            xpathRule = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase" \
                        "/security/rules"

            rule_create_select = query_yes_no("Would you like to add associated rules?")

            if rule_create_select:
                a_addr = raw_input("Enter base name for source address: ")
                a_subnet = unicode(raw_input("Enter subnet in CIDR for the SRC addresses (e.g. '10.1.0.0/16'): "))
                b_addr = raw_input("Enter base name for destination address: ")
                b_subnet = unicode(raw_input("Enter subnet in CIDR for the DST addresses (e.g. '20.1.0.0/16'): "))
                addr_count = raw_input("How many addresses would you like to create? ")

                for x in range(int(addr_count)):
                    a_addr_name = a_addr + "-" + str(x + 1)
                    b_addr_name = b_addr + "-" + str(x + 1)
                    a_subnet = ipaddress.ip_network(a_subnet)
                    b_subnet = ipaddress.ip_network(b_subnet)
                    a_address = a_subnet[x + 1]
                    b_address = b_subnet[x + 1]

                    elementA = '<entry name="' + a_addr_name + '"><ip-netmask>' + str(a_address) + \
                               '</ip-netmask></entry>'
                    elementB = '<entry name="' + b_addr_name + '"><ip-netmask>' + str(b_address) + \
                               '</ip-netmask></entry>'
                    valuesA = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathAddr, 'element': elementA}
                    valuesB = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathAddr, 'element': elementB}

                    send_api_request(url, valuesA)
                    send_api_request(url, valuesB)

                    elementRule = '<entry name="' + a_addr_name + '-' + b_addr_name + '"><to><member>Untrust</member>' \
                                '</to><from><member>Trust</member></from><source><member>' + a_addr_name + \
                                '</member></source><destination><member>' + b_addr_name + '</member></destination>' \
                                '<source-user><member>any</member></source-user><category><member>any</member>' \
                                '</category><application><member>any</member></application><service>' \
                                '<member>application-default</member></service><hip-profiles><member>any</member>' \
                                '</hip-profiles><action>allow</action></entry>'
                    valuesRule = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathRule, 'element': elementRule}

                    send_api_request(url, valuesRule)
            else:
                a_addr = raw_input("Enter base name for new addresses: ")
                a_subnet = unicode(raw_input("Enter subnet in CIDR for the new addresses (e.g. '10.1.0.0/16'): "))
                addr_count = int(raw_input("How many addresses would you like to create? "))

                for x in range(int(addr_count)):
                    addr_name = a_addr + "-" + str(x + 1)
                    subnet = ipaddress.ip_network(a_subnet)
                    address = subnet[x + 1]

                    elementA = '<entry name="' + addr_name + '"><ip-netmask>' + str(address) + '</ip-netmask></entry>'
                    valuesA = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpathAddr, 'element': elementA}

                    send_api_request(url, valuesA)
        else:
            sys.exit()

    print ""
    print "Script finished!"
    print ""


if __name__ == '__main__':
    main()
