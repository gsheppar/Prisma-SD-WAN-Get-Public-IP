#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import ipaddress
import os
import datetime
from datetime import datetime, timedelta
import sys
import csv
from csv import DictReader
import subprocess
from netmiko import ConnectHandler
import string


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example SSH Script'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN
    from cloudgenix_settings import CLOUDGENIX_USERNAME
    from cloudgenix_settings import CLOUDGENIX_PASSWORD

except ImportError:
    CLOUDGENIX_AUTH_TOKEN = None
    CLOUDGENIX_USERNAME = None
    CLOUDGENIX_PASSWORD = None
    

def get_ip(cgx):
    
    ip_address_list = []
    
    for site in cgx.get.sites().cgx_content['items']:
        for element in cgx.get.elements().cgx_content['items']:
            try:
                if element["site_id"] == site["id"]:
                    host_ip = None
                    for interface in cgx.get.interfaces(site_id=site["id"],element_id=element["id"]).cgx_content['items']:
                        if interface["used_for"] == "lan" and interface["scope"] == "global":
                            if interface["ipv4_config"]:
                                host_ip = interface["ipv4_config"]["static_config"]["address"]
                                host_ip = host_ip.split("/", 1)[0]
                                break
                    if host_ip:
                        for interface in cgx.get.interfaces(site_id=site["id"],element_id=element["id"]).cgx_content['items']:
                            if interface["used_for"] == "public":
                                if interface["tags"]:
                                    for tag in interface["tags"]:
                                        if tag == "dhcp_public":
                                            print("Checking interface " + interface["name"] + " on element " + element["name"] + " on site " + site["name"])
                                            interface_name = interface["name"]
                                        
                                            net_connect = ConnectHandler(
                                                device_type="generic",
                                                host=host_ip,
                                                username=CLOUDGENIX_USERNAME,
                                                password=CLOUDGENIX_PASSWORD,
                                            )
    
                                            command = "curl " + interface_name + " ifconfig.me"

                                            output = net_connect.send_command(
                                                command
                                            )
                                            output_list = output.splitlines( )
                                            found_ip = None
                                            for ip_string in output_list:
                                                try:
                                                    ip_object = ipaddress.ip_address(ip_string)
                                                    print(f"The IP address '{ip_object}' is valid.")
                                                    found_ip = ip_object
                                                except ValueError:
                                                    pass
                                            ip_data = {}
                                            ip_data["site_name"] = site["name"]
                                            ip_data["element_name"] = element["name"]   
                                            ip_data["interface_name"] = interface_name
                                            ip_data["interface_ip"] = str(found_ip)
                                            ip_address_list.append(ip_data)
            except:
                print("Failed checking element " + element["name"] + " on site " + site["name"])                                                           
     

    csv_columns = []
    for key in ip_address_list[0]:
        csv_columns.append(key)
    csv_file = "ip_address_list.csv"
    try:
        with open(csv_file, 'w', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in ip_address_list:
                try:
                    writer.writerow(data)
                except:
                    print("Failed to write data for row")
            print("\nSaved ip_address_list.csv file")
    except IOError:
        print("CSV Write Failed")
    
    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        print("Please provide an auth token in cloudgenix_settings.py file")
        return

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    #tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    
    if not CLOUDGENIX_USERNAME or not CLOUDGENIX_PASSWORD:
        print("Please set your username and password in cloudgenix_settings.py file")
        return
    
    get_ip(cgx) 
    # end of script, run logout to clear session.
    print("End of script. Logout!")
    #cgx_session.get.logout()

if __name__ == "__main__":
    go()