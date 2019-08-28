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

#Arguments passed from user input from meta-cnc file
parser = argparse.ArgumentParser(description='Get meta-cnc Params')
parser.add_argument("-f", "--TARGET_IP", help="IP address of the firewall", type=str)
parser.add_argument("-u", "--TARGET_USERNAME", help="Username on NGFW with permission to commit", type=str)
parser.add_argument("-p", "--TARGET_PASSWORD", help="NGFW password", type=str)
parser.add_argument("-l", "--log_forwarding", help="Log Forwarding Profile name", required=True)
parser.add_argument("-d", "--DAG", help="Dynamic Address Group name", required=True)
args = parser.parse_args()

fwHost = args.TARGET_IP
uName = args.TARGET_USERNAME
pWord = args.TARGET_PASSWORD
lfProfile = args.log_forwarding
dag = args.DAG

# Generate API key
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

else:

#Create objects

    #create log forwarding profile
    xpath = "/config/shared/log-settings/profiles/entry[@name='%s']/match-list/entry[@name='Quarantine']" % (lfProfile)
    element = "<log-type>traffic</log-type><filter>All Logs</filter><send-to-panorama>yes</send-to-panorama><actions><entry name='AddQuarantineTag'><type><tagging><action>add-tag</action><tags><member>quarantine</member></tags><target>source-address</target><registration><localhost/></registration></tagging></type></entry></actions>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)
    print("Creating log forwarding profile: " + tree.get('status'))

    #create DAG object
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/dynamic" % (dag)
    element = "<filter>quarantine</filter>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    dag_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(dag_create_r.text)
    print("Creating Dynamic Address Group: " + tree.get('status'))

#Create Security Rules

    #create sinkhole traffic security rule
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='SinkholeTraffic']"
element = "<from><member>trust</member></from><to><member>untrust</member></to><destination><member>Sinkhole-IPv4</member><member>Sinkhole-IPv6</member></destination><application><member>any</member></application><service><member>any</member></service><category><member>any</member></category><source><member>any</member></source><action>allow</action><log-setting>%s</log-setting>" % (lfProfile)
values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
sinkhole_rule_create = requests.post(palocall, data=values, verify=False)
tree = ET.fromstring(sinkhole_rule_create.text)

    #move sinkhole rule after Inbound Block Rule
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='SinkholeTraffic']"
values = {'type': 'config', 'action': 'move', 'xpath': xpath, 'where': 'after', 'dst': 'Inbound Block Rule', 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
move = requests.get(palocall, params=values, verify=False)
tree = ET.fromstring(move.text)

    #isolation security rule
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='IsolateQuarantinedHosts']"
element = "<from><member>trust</member></from><to><member>untrust</member></to><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><category><member>any</member></category><source><member>%s</member></source><action>deny</action><log-setting>default</log-setting>" % (dag)
values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
rule_create_r = requests.post(palocall, data=values, verify=False)
tree = ET.fromstring(rule_create_r.text)

    #move isolation rule to the top
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='IsolateQuarantinedHosts']"
values = {'type': 'config', 'action': 'move', 'xpath': xpath, 'where': 'top', 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
move = requests.get(palocall, params=values, verify=False)
tree = ET.fromstring(move.text)
print("Populating Security Rules and Moving to the Top of Policy: " + tree.get('status'))

#Commit Changes to the NGFW
cmd = '<commit><force></force></commit>'
values = {'type:': 'commit', 'cmd': cmd, 'key': apiKey}
commit_call = 'https://%s/api/' % (fwHost)
commit_r = requests.post(commit_call, data=values, verify=False)
tree = ET.fromstring(commit_r.text)
jobid = tree[0][1].text
print("Committing Policy (JobID): " + str(jobid))

print(r'''\ Now go forth and create havoc on your Win7 Victim!

  ____            _        _     ____                        _
 |  _ \ __ _  ___| | _____| |_  |  _ \ _   _ _ __ __ _  __ _| |_ ___  _ __ _   _
 | |_) / _` |/ __| |/ / _ \ __| | |_) | | | | '__/ _` |/ _` | __/ _ \| '__| | | |
 |  __/ (_| | (__|   <  __/ |_  |  __/| |_| | | | (_| | (_| | || (_) | |  | |_| |
 |_|   \__,_|\___|_|\_\___|\__| |_|    \__,_|_|  \__, |\__,_|\__\___/|_|   \__, |
                                                 |___/                     |___/
                       ______
                    .-"      "-.
                   /            \
       _          |              |          _
      ( \         |,  .-.  .-.  ,|         / )
       > "=._     | )(__/  \__)( |     _.=" <
      (_/"=._"=._ |/     /\     \| _.="_.="\_)
             "=._ (_     ^^     _)"_.="
                 "=\__|IIIIII|__/="
                _.="| \IIIIII/ |"=._
      _     _.="_.="\          /"=._"=._     _
     ( \_.="_.="     `--------`     "=._"=._/ )
      > _.="                            "=._ <
     (_/   ssw                              \_)
                                         ''')
