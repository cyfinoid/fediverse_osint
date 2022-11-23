#!/usr/bin/env python3
import argparse
import reprlib

import requests
import validators
from urllib.parse import urlparse
import json
from datetime import timedelta, datetime

nodelist_url = "https://nodes.fediverse.party/nodes.json"


def is_file_older_than(file, delta):
    cutoff = datetime.utcnow() - delta
    mtime = datetime.utcfromtimestamp(os.path.getmtime(file))
    if mtime < cutoff:
        return True
    return False


def is_instance_birdsitelive(domain):
    try:
        r = requests.get("https://" + domain + "/.well-known/nodeinfo")
        if r.status_code == 200:
            x = json.loads(r.text)
            detail_url = x["links"][0]["href"]
            r = requests.get(detail_url)
            # print(r.text)
            inst_data = json.loads(r.text)
            if inst_data["software"]["name"] == "birdsitelive":
                return True
            else:
                return False
        else:
            return False
    except:
        return True


def get_domain_and_id(inp):
    if validators.url(inp):
        print("[+] " + inp + " is Url")
        link = urlparse(inp)
        # print(link)
        domain_name = link.netloc
        if link.path.__contains__("@"):
            username = link.path[2:]
    else:
        print("[*] " + inp + " is NOT a URL")
        if inp.__contains__("@"):
            # remove the first @ in case it exists
            if inp[:1] == "@":
                email = inp[1:]
            else:
                email = inp
            domain_name = email[email.index('@') + 1:]
            username = email[: email.index('@')]
        else:
            print("[-] Nor an email")
            username = ""
            domain_name = ""

    return username, domain_name


def check_domain(domain):
    r = requests.get("https://" + domain + "/.well-known/nodeinfo")
    # print(r.text)
    if r.status_code == 200:
        return True
    else:
        return False


def fetch_details(domain):
    r = requests.get("https://" + domain + "/.well-known/nodeinfo")
    x = json.loads(r.text)
    detail_url = x["links"][0]["href"]
    r = requests.get(detail_url)
    # print(r.text)
    inst_data = json.loads(r.text)
    return inst_data


def parse_domain_details(inst_data):
    try:
        name = inst_data["software"]["name"]
        print("[+] Software Name: ", name)
        version = inst_data["software"]["version"]
        print("[+] Software Version:", version)
        protocols_supported = inst_data["protocols"]
        print("[+] Protocols Supported:", protocols_supported[0])
        protocol_version = inst_data["version"]
        print("[+] Protocol Version: ", protocol_version)
        reg_open = inst_data["openRegistrations"]
        print("[+] Registration Status: ", reg_open)
        if inst_data["usage"]["users"]:
            total_users = inst_data["usage"]["users"]["total"]
            print("[+] Total Users: ", total_users)
            active_users = inst_data["usage"]["users"]["activeMonth"]
            print("[+] Monthly Active Users: ", active_users)
        else:
            print("[*] Single User instance or info not available")

    except KeyError:
        print("[*] Error occured")
        print(inst_data)


def check_user(username, domain):
    r = requests.get("https://" + domain + "/.well-known/webfinger?resource=acct:" + username + "@" + domain)
    if r.status_code == 200:
        return True
    else:
        return False


def fetch_user_details(username, domain):
    r = requests.get("https://" + domain + "/.well-known/webfinger?resource=acct:" + username + "@" + domain)
    x = json.loads(r.text)
    # print(json.dumps(x, indent=4))
    lnk = x["links"]
    for i in lnk:
        if i["rel"].__contains__("profile"):
            print("[+] User Profile : " + i["href"])


def hunt_name(name_hunt):
    f = open('nodes.json', 'r')
    full_list = json.load(f)
    for i in full_list:
        # print("Checking: " + i)
        if is_instance_birdsitelive(i):
            print("[*] Skipping Bird Site Live instance " + i)
        else:
            try:
                r = requests.get("https://" + i + "/.well-known/webfinger?resource=acct:" + name_hunt + "@" + i)
                if r.status_code == 200:
                    x = json.loads(r.text)
                    if "aliases" in x:
                        if x["subject"] == "acct:" + name_hunt + "@" + i:
                            print("[+] User found on : " + i + " Details: " + ','.join(x["aliases"]))
                        else:
                            print("[*] Misconfigured Server : " + i)
            except:
                print("[*] Connection Error : " + i)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="URL to start with", required=False)
    parser.add_argument("-s", "--search", help="User Id to search across fediverse", required=False)
    parser.add_argument("-u", "--update", help="Update list of nodes from fediverse.party", required=False)
    args = parser.parse_args()
    if args.input:
        inp = args.input
        username, domain = get_domain_and_id(inp)
        # print("Lets check if domain is a fediverse entity or not")
        if check_domain(domain):
            print("[+] Valid entity, Proceeding with detail extraction")
            # print("Lets get details about the domain")
            domain_details = fetch_details(domain)
            parse_domain_details(domain_details)
            # print("lets confirm Users existance")
            if check_user(username, domain):
                fetch_user_details(username, domain)
            else:
                print("[-] User Doesnt Exists")
        else:
            print("Not a fediverse entity")
    if args.update:
        print("lets check if update is needed: new file to be fetched if last update was more then 6 hours older")
        if is_file_older_than("nodes.json", timedelta(hours=10)):
            node_list = requests.get(nodelist_url)
            if node_list.status_code == 200:
                open('nodes.json', 'w').write(node_list.text)
            else:
                print("[*] Error while updating file")
    if args.search:
        name_hunt = args.search
        print("Lets hunt for the username " + name_hunt)
        hunt_name(name_hunt)


if __name__ == "__main__":
    main()
