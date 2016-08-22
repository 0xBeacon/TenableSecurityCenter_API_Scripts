#!/usr/bin/python
#------------------------------------------------------------------
# Tenable SecurityCenter 5.x API Scan Launch Script
# 
# Script created for scan automation for server provisioning.
# Additional functionality will be added in subsequent versions.
#
#
# TODO: 
#   -Add back functions to pull results (or put them in another script)
#   -Add email option for scan results
#   -Add a check to make sure the right packages are intalled before running
#   -Add checks to verify existence of sc, username, password variables 
#------------------------------------------------------------------

__version__ = '0.0.1'
__author__ = 'Chris Eckert'

import requests
import json
import sys
import base64
import argparse

# Help Menu
#-------------------------------------------------------------------
def usage():
    print("Tenable SecurityCenter 5.x API Scan Launch Script")
    print("Version: {0}".format(__version__))
    print("Usage: scan_launch.py <options>\n")
    print("Options:")
    print("***Below is the only option for this version of the script.  Additional funcionality will be added later.")
    print("")
    print("   -s, --scan <host(s)>")
    print("              Target hosts. Can be IP, multiple IPs (comma separated), or CIDR.")
    print("              ***Do not use DNS, FQDN, or hostname.***")
    print("")
    print("Examples:")
    print("python scan_launch.py -s 10.10.10.10")
    print("python scan_launch.py -s '10.10.10.10,11.11.11.11,12.12.12.12'")
    print("python scan_launch.py -s 10.10.10.0/24")
    print("")

# Definitions 
#-------------------------------------------------------------------
#Security Center Info
username = 'api'                                    #<-----Edit this line
password = 'password'                               #<-----Edit this line
url = 'https://securitycenter/rest/'                #<-----Edit this line
headers = {'Content-type': 'application/json'}

# Proxy
#-------------------------------------------------------------------
# Used for debugging communication with SecurityCenter
whichproxy = 'fiddler'
if whichproxy == 'fiddler':
    proxy = {
              "http"  : "http://127.0.0.1:8888",
              "https" : "https://127.0.0.1:8888",
            }
elif whichproxy == 'burp':
    proxy = {
              "http"  : "http://127.0.0.1:8080",
              "https" : "https://127.0.0.1:8080",
            }
else:
    proxy = {
              "http": None,
              "https": None,
            }

#------------------------------------------------------------------
# HTTP POST JSON Query Section
#
# Here there be unicorns. (aka human readable JSON)
# Many of these fields are likely unnecessary, but were taken
# straight from browser requests.  I may clean these up later.
#------------------------------------------------------------------

scan_json = {
        "id":63,                                   #<-----Edit this line
        "name":"API_AUTOMATION",
        "description":"",
        "context":"",
        "status":0,
        "createdTime":"",
        "modifiedTime":"",
        "group":{
                "id":0,
                "name":"Administrator"},
        "groups":[],
        "tags":"",
        "repository":{},
        "schedule":{
                    "start":"TZID=:Invalid dateInvalid date",
                    "repeatRule":"FREQ=TEMPLATE;INTERVAL=",
                    "type":"template"},
        "dhcpTracking":"false",
        "emailOnLaunch":"true",
        "emailOnFinish":"true",
        "type":"policy",
        "policy":{
                "id":"1000001"},
        "plugin":{
                "id":-1,
                "name":"",
                "description":""},
        "zone":{
                "id":-1},
        "timeoutAction":"rollover",
        "rolloverType":"template",
        "scanningVirtualHosts":"false",
        "classifyMitigatedAge":0,
        "assets":[],
        "ipList":"",
        "maxScanTime":"unlimited"
        }


# Functions
#------------------------------------------------------------------
#Grab Authentication Token
def grab_token():
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.request('post', url+'token',
                    json={'username': username, 'password': password},
                    headers=headers,
                    #proxies=proxy,
                    verify=False)
        global cookie
        cookie = dict(TNS_SESSIONID=(r.cookies['TNS_SESSIONID']))
        token = r.json()['response']['token']
        tokenized_header = {'X-SecurityCenter': str(token)}
        headers.update(tokenized_header)
        if token == None:
        	print "[-] Something is wrong with grabbing a token."
        	sys.exit(1)
        else:
        	print "[+] Token successfully grabbed."
    except Exception, e:
        print str(e)
        sys.exit(1)

#Update API_AUTOMATION Asset group prior to scan.
#TODO: check that asset group exits first.
def update_asset(scan):
    try:
        requests.packages.urllib3.disable_warnings()
        asset = {
        "definedIPs":scan
        }
        s = requests.request('patch', url + 'asset/497',      #<----Edit this line
                    headers=headers,
                    cookies=cookie,
                    #proxies=proxy,
                    verify=False,
                    json=asset)
        if s.status_code == 403:
        	print "[-] Something is wrong with the asset group update. Verify that you are using an IP address and not DNS name."
        	sys.exit(1)   
        else:
        	print "[+] Asset group successfully updated."
        	asset_response = s.json()['response']['typeFields']
    except Exception, e:
        print str(e)
        sys.exit(1)

#Obvious.  --scan arg        
def launch_scan():
    try:
        requests.packages.urllib3.disable_warnings()
        s = requests.request('post', url + 'scan/63/launch',   #<----Edit this line
                    headers=headers,
                    cookies=cookie,
                    #proxies=proxy,
                    verify=False,
                    json=scan_json)
        scan_response = s.json()['response']
        if "Invalid" in str(scan_response):
        	print "[-] Something is wrong with the scan launch."
        else:
        	print "[+] Scan successfully launched."
    except Exception, e:
        print str(e)
        sys.exit(1)

# Main
#------------------------------------------------------------------
def main():
    # 
    #-----------------------------------------------------------------
    # Define Parser Options 
    parser = argparse.ArgumentParser(description="Remove -h for better help menu.")
    parser.add_argument('-s','--scan', type=str,  required=False)
    args = parser.parse_args()
    scan = args.scan

    if scan == None:
        usage()
    else:
        grab_token()
        update_asset(scan)
        launch_scan()
        

if __name__ == "__main__":
    main()



