#!/usr/bin/python

"""
name: pan-test-policy
description: Test security policy based on CSV data
author: Steve Barber
company: Palo Alto Networks
prerequisites: python 2.7.5+ with the libraries listed in the 'import' statements.
last updated: 10/24/2017

Change log:
** 1.0 - created script

"""

libnames = ['getpass', 'argparse', 'string', 'urllib', 'urllib2', 'ssl', 'httplib', 'os', 'csv']
for libname in libnames:
    try:
        lib = __import__(libname)
    except:
        print sys.exc_info()
    else:
        globals()[libname] = lib
try:
    from xml.dom import minidom
    from random import *
    from lxml import etree
    import xml.etree.ElementTree as ET
except ImportError:
    raise ImportError("Module 'lxml' is required.  Verify that it is installed and try again.")


ssl._create_default_https_context = ssl._create_unverified_context

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="Name or IP address of the firewall/Panorama")
parser.add_argument("-f", "--filename", help="Log file name")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
parser.add_argument("-t", "--tab", help="Tab delimited log file", action='store_true')
args = parser.parse_args()

print '\n'

try:
    if args.ip:
        ip = args.ip
    else:
        ip = raw_input("Enter the name or IP of the firewall/Panorama: ")
    if args.filename:
        file = args.filename
    else:
        file = raw_input("Enter the log filename: ")
    if args.username:
        user = args.username
    else:
        user = raw_input("Enter the user login: ")
    if args.password:
        pw = args.password
    else:
        pw = getpass.getpass()
    if args.tab:
        tdelimited = True
    else:
        tdelimited = False

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


def read_csv(ip, key):

    csvcmd = ""
    if tdelimited:
        csvfile = open(file, 'rU')
        reader = csv.DictReader(csvfile, delimiter='\t')
        header = reader.fieldnames
        # ** DEBUG - Print column headers **
        # print header
    else:
        csvfile = open(file, 'rU')
        reader = csv.DictReader(csvfile)
        header = reader.fieldnames
        # ** DEBUG - Print column headers **
        # print header

    i = 1

    for row in reader:
        i = i + 1
        for item in header:
            try:
                if row['Source address']:
                    csvcmd = '<source>' + row['Source address'] + '</source>'
                if row['Source Zone']:
                    csvcmd = csvcmd + '<from>' + row['Source Zone'] + '</from>'
                if row['Destination address']:
                    csvcmd = csvcmd + '<destination>' + row['Destination address'] + '</destination>'
                if row['Destination Zone']:
                    csvcmd = csvcmd + '<to>' + row['Destination Zone'] + '</to>'
                if row['Source User']:
                    csvcmd = csvcmd + '<source-user>' + row['Source User'] + '</source-user>'
                if row['Application']:
                    csvcmd = csvcmd + '<application>' + row['Application'] + '</application>'
                if row['Destination Port']:
                    csvcmd = csvcmd + '<destination-port>' + row['Destination Port'] + '</destination-port>'
                if row['IP Protocol']:
                    if row['IP Protocol'] == 'tcp':
                        csvcmd = csvcmd + '<protocol>6</protocol>'
                    if row['IP Protocol'] == 'udp':
                        csvcmd = csvcmd + '<protocol>17</protocol>'
                    if row['IP Protocol'] == 'icmp':
                        csvcmd = csvcmd + '<protocol>1</protocol>'
                    if row['IP Protocol'] == 'esp':
                        csvcmd = csvcmd + '<protocol>50</protocol>'
                    if row['IP Protocol'] == 'ah':
                        csvcmd = csvcmd + '<protocol>51</protocol>'
                if row['Category']:
                    # ** Placeholder for Categories - custom categories error out.  possible bug **
                    # csvcmd = csvcmd + '<category>' + row['Category'] + '</category>'
                    csvcmd = csvcmd + '<category>any</category>'
            except:
                pass

        conn = httplib.HTTPSConnection(ip, context=ssl._create_unverified_context())
        request_str = "/api/?type=op&cmd=<test><security-policy-match>" + csvcmd + "</security-policy-match></test>&key="

        conn.request("GET", request_str + key)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        r.close()

        try:
            opresponse = etree.fromstring(data)

            for x in opresponse.iter():
                if x.tag == "response":
                    if not x.attrib["status"] == "success":
                        print "Test failed.  Check the firewall system log for more details."
                if x.tag == "rules":
                    if not len(x):
                        print "Row " + str(i) + " result: Rule not matched!"
                    else:
                        for child in x:
                            print "Row " + str(i) + " result: " + child.text
        except:
            print "Error parsing XML response."
            pass

        # ** DEBUG - print API request string**
        # print request_str + key
        # print '\n'


def main():

    key = get_api_key(ip, user, pw)
    hostname, mode = get_sys_info(ip, key)
    print ""
    print ""
    # ** DEBUG - print user API key **
    #print "API key for user '" + user + "' = " + key
    read_csv(ip, key)
    print ""
    print "Script finished!"
    print ""


if __name__ == '__main__':
    main()
