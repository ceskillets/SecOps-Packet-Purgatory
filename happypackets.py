#!/usr/bin/env python3
DOCUMENTATION = '''
Copyright (c) 2019, Palo Alto Networks

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Author: Sandy Wenzel <swenzel@paloaltonetworks.com>
'''

import argparse
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as ET


def get_key(fwHost, uName, pWord):
    '''
    generates the API key for the NGFW
    '''
    call = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwHost,uName,pWord)
    try:
        r = requests.get(call, verify=False)
        tree = ET.fromstring(r.text)
        if tree.get('status') == "success":
            apiKey = tree[0][0].text

    except requests.exceptions.ConnectionError as e:
        print("There was a problem connecting to the firewall.  Please check the connection information and try again.")
        try:
            apiKey
        except NameError as e:
            print("There was a problem connecting to the firewall.  Please check the connection information and try again.")

    return(apiKey)


def import_urlresponse(fwHost, apiKey, filename):
    '''
    import the custom URL Override page (url-coach-text)
    '''
    values = {'type': 'import', 'category': 'url-coach-text', 'key': apiKey}
    api_url = 'https://%s/api/' % (fwHost)
    files = {'file': open('{0}'.format(filename), 'rb')}
    import_r = requests.post(api_url, data=values, files=files, verify=False)
    tree = ET.fromstring(import_r.text)
    print('Importing Custom URL Response Page: ' + tree.get('status'))


def log_forward(fwHost, urlLogProfile, apiKey):
    '''
    create the Log-Forwarding Profile to match on the override and remove the 'quarantine' tag
    '''
    xpath = "/config/shared/log-settings/profiles/entry[@name='%s']/match-list/entry[@name='UNQuarantine']" % (urlLogProfile)
    element = "<log-type>url</log-type><filter>(action eq override)</filter><send-to-panorama>yes</send-to-panorama><actions><entry name='RemoveQuarantineTag'><type><tagging><action>remove-tag</action><tags><member>quarantine</member></tags><target>source-address</target><registration><localhost/></registration></tagging></type></entry></actions>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)
    print('Creating Log Forwarding Profile: ' + tree.get('status'))

    return(lfp_create_r)


def urlf_override(fwHost, urlProfile, apiKey):
    '''
    create the URL Filtering profile and set all available pre-defined categories to 'override'
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering"
    element = "<entry name='%s'/>" % (urlProfile)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    url_pw_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(url_pw_r.text)
    print('Creating URL Filtering Profile: ' + tree.get('status'))

    #get URL categories
    categories = []

    xpath = "/config/predefined/pan-url-categories"
    values = {'type': 'config', 'action': 'get', 'xpath': xpath, 'key': apiKey}
    collect_call = 'https://%s/api/' % (fwHost)
    r = requests.get(collect_call, params=values, verify=False)
    tree = ET.fromstring(r.text)
    for element in tree[0]:
        entries = element.findall('entry')
        for entry in entries:
            category = entry.get('name')
            categories.append (str(category))

    #set categories to override
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering/entry[@name='%s']/override" % (urlProfile)
    element = ""
    for category in categories:
        element += "<member>%s</member>" % (category)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    override_call = 'https://%s/api/' % (fwHost)
    r = requests.post(override_call, data=values, verify=False)
    tree = ET.fromstring(r.text)
    print('Setting URL Categories to Override: ' + tree.get('status'))

    return(r)


def url_redirect(fwHost, apiKey):
    '''
    set the url-admin-override password and configure the redirect to the NGFW ethernet1/2 IP
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/url-admin-override"
    element = "<password>paloalto</password><mode><redirect><address>192.168.45.20</address></redirect></mode>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    redirect_call = 'https://%s/api/' % (fwHost)
    url_redirect_r = requests.post(redirect_call, data=values, verify=False)
    tree = ET.fromstring(url_redirect_r.text)
    print('Setting Override Password and Configuring Redirect: ' + tree.get('status'))

    return(url_redirect_r)


def url_policy(fwHost, apiKey, dag, urlLogProfile, urlProfile):
    '''
    create a security policy that looks for the matching override tag to remove a host from quarantine
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='OverrideQuarantine']"
    element = "<from><member>trust</member></from><source><member>%s</member></source><to><member>any</member></to><destination><member>any</member></destination><application><member>web-browsing</member><member>ssl</member></application><service><member>application-default</member></service><action>allow</action><log-setting>%s</log-setting><profile-setting><profiles><url-filtering><member>%s</member></url-filtering></profiles></profile-setting>" % (dag, urlLogProfile, urlProfile)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    rule_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(rule_create_r.text)

    #move Security Rule to the Top
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='OverrideQuarantine']"
    values = {'type': 'config', 'action': 'move', 'xpath': xpath, 'where': 'top', 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    move = requests.get(palocall, params=values, verify=False)
    tree = ET.fromstring(move.text)
    print("Populating Override Security Rule and Moving to the Top of Policy: " + tree.get('status'))

    return(move)

def commit(fwHost, apiKey):
#Commit Changes to the NGFW
    cmd = '<commit><force></force></commit>'
    values = {'type:': 'commit', 'cmd': cmd, 'key': apiKey}
    commit_call = 'https://%s/api/' % (fwHost)
    commit_r = requests.post(commit_call, data=values, verify=False)
    tree = ET.fromstring(commit_r.text)
    jobid = tree[0][1].text
    print("Committing Policy (JobID): " + str(jobid))
    print(r'''\ Go rescue your host(s) from packet jail!
    _________________________
        ||   ||     ||   ||
        ||   ||, , ,||   ||
        ||  (||/|/(\||/  ||
        ||  ||| _'_`|||  ||
        ||   || o o ||   ||
        ||  (||  - `||)  ||
        ||   ||  =  ||   ||
    ssw ||   ||\___/||   ||
        ||___||) , (||___||
       /||---||-\_/-||---||\
      / ||--_||_____||_--|| \
     (_(||)-|UID: nzuk|-(||)_)
     |"""""""""""""""""""""""""""|
     | "But...but...the e-mail   |
     | said I would get millions |
     | for aiding a prince with  |
     | a wire transfer!"         |
      """""""""""""""""""""""""""''')
    return(commit_r)

def main ():
    #Arguments passed from user input from meta-cnc file
    parser = argparse.ArgumentParser(description='Get meta-cnc Params')
    parser.add_argument("-f", "--TARGET_IP", help="IP address of the firewall", required=True)
    parser.add_argument("-u", "--TARGET_USERNAME", help="Admin user for NGFW", required=True)
    parser.add_argument("-p", "--TARGET_PASSWORD", help="Password for NGFW", required=True)
    parser.add_argument("-l", "--url_forwarding", help="Log Forwarding Profile name", required=True)
    parser.add_argument("-a", "--url_profile", help="URL Profile name for new security profile", required=True)
    parser.add_argument("-c", "--url_custom", help="Use Custom URL Page", required=True)
    parser.add_argument("-d", "--DAG", help="Dynamic Address Group name from Step-1", required=True)
    args = parser.parse_args()

    fwHost = args.TARGET_IP
    uName = args.TARGET_USERNAME
    pWord = args.TARGET_PASSWORD
    urlLogProfile = args.url_forwarding
    urlProfile = args.url_profile
    urlCustom = args.url_custom
    dag = args.DAG

    filename = 'url_override.html'

    #get firewall API key
    apiKey = get_key(fwHost, uName, pWord)

    #import the URL response page
    if urlCustom == 'custom':
        import_urlresponse(fwHost, apiKey, filename)
        print('Importing Custom URL Filtering Override Page')

    else:
        print('Using the system default URL Filtering Override Page')

    #Create URL Log-Forwarding Profile
    good_create = log_forward(fwHost, urlLogProfile, apiKey)
    if 'success' not in good_create.text:
        print('ERROR creating Log Forwarding Profile')
        exit(1)

    #Create URL Filtering profile and set categories to override_call
    good_override = urlf_override(fwHost, urlProfile, apiKey)
    if 'success' not in good_override.text:
        print('ERROR creating URL Filtering Profile')
        exit(1)

    #set url-admin-override password and redirect
    good_redirect = url_redirect(fwHost,apiKey)
    if 'success' not in good_redirect.text:
        print('ERROR setting Override Password and Redirect')
        exit(1)

    #Create URL Override Security Rule and Move rule to the Top
    good_policy = url_policy(fwHost, apiKey, dag, urlLogProfile, urlProfile)
    if 'success' not in good_policy.text:
        print('ERROR creating security policy')
        exit(1)

    #commit config
    commit(fwHost, apiKey)

if __name__ == '__main__':
        main()
