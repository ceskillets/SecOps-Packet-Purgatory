# Packet Purgatory Skillet
This is the initial release of the Packet Purgatory Skillet. Huge shout-out to Mitch Densley for helping with the logic and workflow of this skillet.

#### Purpose:
This skillet can be used to demo the auto-tagging feature in PAN-OS 9.x NGFW and onward by detecting and quarantine a host that is actively communicating to C2. This would closely mimic a customer environment by using an internal DNS server. It will auto-tag the host into a dynamic address group and isolate them in a security rule that is set to deny __without__ impacting and sinkholing the internal DNS server. For an in depth review on the DNS Sinkhole feature please refer to the Palo Alto Networks Live Community: [Learning Happy Hour Episode 13](https://youtu.be/FUFtEEMEE00).


#### Requirements and Dependencies:
This demo is based off of the resources available in the SE LiAB v2.x. You will need these host VM's up and running in order to execute the demo:
* msft-esm-dc (Internal DNS server and UID Server)
* msft-victim-7 (Query all the bad thingz)
* pan-panos-vm50
  * Must have the [Home Skillet](https://github.com/PaloAltoNetworks/HomeSkillet.git) pre-loaded
  * *(Optional)* There is a custom URL Override Page that is available to select during the provisioning of this skillet

It is assumed that you have all the appropriate content updates already installed for the PA-VM as well as active subscriptions for Threat Prevention and URL Filtering (DNS Subscription is optional).


#### How to _SEND IT_:
First step is to import this repository into Panhandler. Panhandler will push the configuration items to the specified environment. Panorama is not required as the skillet config is pushed directly to the PA-VM. The Logs, however, are configured to be forwarded to Panorama to provide additional log data for any future demos of Panorama.

###### [Step-1] - Quarantine
1. Fill out the required fields and hit "Submit"
 * Take note of the dyanmic address group (DAG) name! This will be carried over into Step-2
2. Verify the configurations have been pushed to the NGFW - you should now see:
* 2-new security rules at the top of the policy
* A log forwarding profile
* A dynamic address group (DAG) and confirm this is empty
3. On the msft-victim-7:
* Verify and validate you have Internet connectivity (surf the webz, ping various hosts, etc.)
* Mimic malicious activity by performing 'nslookup' and/or 'ping -t' on a malicious domain (you can find a working list by checking the Anti-Virus Release Notes within the content updates of the NGFW. Search for the header *New Spyware DNS C2 Signatures*)
```
nslookup <baddomain>
ping -t <baddomian>
```
* You should see the NGFW answering the request with *sinkhole.paloaltonetworks.com*. The IP address will change over time. This is the expected behavior to avoid being blacklisted.
4. On the NGFW
* Check the dyanmic address group in the NGFW to see if the host has been populated
* *back on the msft-victim-7:* Open an Incognito browser session and try to surf around (at this point the host should be quarantined)
* Check the traffic logs to verify the host is indeed in packet purgatory

__Step-1 of the Demo is Now Complete__

###### [Step-2] - Override
**You should not proceed with this step until Step-1 has loaded succesfully and you were able to execute the demo**
1. Fill out the required fields and hit "Submit"
* Remember when I said to take note of the DAG name?!
2. Verify the configurations have been pushed to the NGFW - you should now see:
* 1-new security rules at the top of the policy
* Another log forwarding profile added
* A URL Filtering security profile with all categories listed under *Override Categories*
3. On the poor, lonely, isolated msft-victim-7:
* Open an Incognito browser session and attempt to browse a website
* You should now see the override page (the password is the default password for the lab - if you forget it's also in the script :-))

Huzzah! The host has been rescued!

__This Concludes the Demo__   


## Support Policy
The code and templates in the repo are released under an as-is, best effort,
support policy. These scripts should be seen as community supported and
Palo Alto Networks will contribute our expertise as and when possible.
We do not provide technical support or help in using or troubleshooting the
components of the project through our normal support options such as
Palo Alto Networks support teams, or ASC (Authorized Support Centers)
partners and backline support options. The underlying product used
(the VM-Series firewall) by the scripts or templates are still supported,
but the support is only for the product functionality and not for help in
deploying or using the template or script itself. Unless explicitly tagged,
all projects or work posted in our GitHub repository
(at https://github.com/PaloAltoNetworks) or sites other than our official
Downloads page on https://support.paloaltonetworks.com are provided under
the best effort policy.
