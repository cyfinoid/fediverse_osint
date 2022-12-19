#!/usr/bin/env python3
import argparse
import requests
import validators
from urllib.parse import urlparse
import json
from datetime import timedelta, datetime
import time
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from tqdm import tqdm
import re
import os

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0 fediverse_osint'
}

start = time.perf_counter()

nodelist_url = "https://nodes.fediverse.party/nodes.json"


def is_file_older_than(file, delta):
    cutoff = datetime.utcnow() - delta
    mtime = datetime.utcfromtimestamp(os.path.getmtime(file))
    if mtime < cutoff:
        return True
    return False


def is_invalid_instance(domain):
    # Returns False only when specific conditions are met, any error is a return True automatically
    # 1. its responding to nodeinfo
    # 2. its not birdsitelive
    try:
        r = requests.get("https://" + domain + "/.well-known/nodeinfo", headers=headers, timeout=2)
        # if nodeinfo not responding no point going further
        if r.status_code == 200:
            x = json.loads(r.text)
            detail_url = x["links"][0]["href"]
            r = requests.get(detail_url, headers=headers, timeout=2)
            # print(r.text)
            inst_data = json.loads(r.text)
            # if its a birdsitelive instance no point going further
            if inst_data["software"]["name"] == "birdsitelive":
                return True
            else:
                return False
        else:
            return True
    except:
        return True


def get_domain_and_id(inp):
    if validators.url(inp):
        link = urlparse(inp)
        # print(link)
        domain_name = link.netloc
        if link.path.__contains__("@"):
            username = link.path[2:]
        elif link.path.__contains__("users"):
            username = link.path[link.path.rfind("/") + 1:]
        else:
            username = ""
    else:
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
    try:
        r = requests.get("https://" + domain + "/.well-known/nodeinfo", headers=headers, timeout=2)
        # print(r.text)
        if r.status_code == 200:
            return True
        else:
            return False
    except:
        return False


def fetch_details(domain):
    r = requests.get("https://" + domain + "/.well-known/nodeinfo", timeout=2, headers=headers)
    x = json.loads(r.text)
    detail_url = x["links"][0]["href"]
    r = requests.get(detail_url, headers=headers, timeout=2)
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
        # reg_open = inst_data["openRegistrations"]
        # print("[+] Registration Status: ", reg_open)
        if inst_data["usage"]["users"]:
            total_users = inst_data["usage"]["users"]["total"]
            print("[+] Total Users: ", total_users)
            active_users = inst_data["usage"]["users"]["activeMonth"]
            print("[+] Monthly Active Users: ", active_users)
        else:
            print("[⛔] Single User instance or info not available")

    except KeyError:
        print("[⛔] Error occured")
        print(inst_data)


def check_user(username, domain):
    r = requests.get("https://" + domain + "/.well-known/webfinger?resource=acct:" + username + "@" + domain, timeout=2,
                     headers=headers)
    if r.status_code == 200:
        return True
    else:
        return False


def fetch_user_data(url, req_type):
    headers["Accept"] = req_type
    r = requests.get(url, timeout=2, headers=headers)
    return r.json()


def fetch_user_details(username, domain):
    r = requests.get("https://" + domain + "/.well-known/webfinger?resource=acct:" + username + "@" + domain, timeout=2,
                     headers=headers)
    x = json.loads(r.text)
    # print(json.dumps(x, indent=4))
    lnk = x["links"]
    for i in lnk:
        if i["rel"].__contains__("profile"):
            print("[✅] User Profile : " + i["href"])
        if "type" in i and i["type"].__contains__("json"):
            print("[✅] User Data here : " + i["href"])
            udata = fetch_user_data(i["href"], i["type"])
            if udata:
                print("[✅] ====== Details Start =======")
                if "name" in udata:
                    print("[+] Name: " + udata["name"])
                if "summary" in udata:
                    print("[+] Summary: " + str(udata["summary"]))
                if "preferredUsername" in udata:
                    print("[+] Preferred Username: " + udata["preferredUsername"])
                if "attachment" in udata:
                    for x in udata["attachment"]:
                        print(re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', x["value"]))
                print("[✅] ====== Details End =======")


def hunt_name(name_hunt):
    f = open('nodes.json', 'r')
    full_list = json.load(f)
    print("starting threadpool")
    with tqdm(total=len(full_list)) as pbar:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = [executor.submit(huntfunc, i, name_hunt) for i in full_list]
            try:
                for f in as_completed(results):
                    pbar.update(1)
                    if f.result() != None:
                        if f.result() != False:
                            print(f.result())
            except KeyboardInterrupt:
                print("Ctrl C recieved : Exiting gracefully : Press Ctrl + C for immediate termination")
                executor._threads.clear()
                concurrent.futures.thread._threads_queues.clear()
                executor.shutdown(cancel_futures=True)

    for f in concurrent.futures.as_completed(results):
        if f.result() and f.result() is not None:
            print(f.result())


def huntfunc(i, name_hunt):
    try:
        if is_invalid_instance(i):
            return False
        r = requests.get("https://" + i + "/.well-known/webfinger?resource=acct:" + name_hunt + "@" + i, timeout=2,
                         headers=headers)
        if r.status_code == 200:
            x = json.loads(r.text)
            if "aliases" in x:
                # This is needed to eliminate the scenario where user has put in a fake
                # web finger response. this ensures that acct is matching to what we asked for.
                if x["subject"] == "acct:" + name_hunt + "@" + i:
                    try:
                        for nm in x["aliases"]:
                            r = requests.get(nm, headers=headers, timeout=2);
                            # This check removes the false positives where the node suggests 
                            # user exists but the profile has a 404 found a few culprits in the system
                            if r.status_code != 200:
                                return False
                    except:
                        return False
                    return '[✅] User found on : ' + i + ' Details: ' + ', '.join(x["aliases"])
                else:
                    return False
    except:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="URL to start with", required=False)
    parser.add_argument("-s", "--search", help="User Id to search across fediverse", required=False)
    parser.add_argument("-u", "--update", help="Update list of nodes from fediverse.party", required=False,
                        action='store_true')
    args = parser.parse_args()
    if args.input:
        inp = args.input
        username, domain = get_domain_and_id(inp)
        # print("Lets check if domain is a fediverse entity or not")
        if check_domain(domain):
            print("[✅] Valid entity, Proceeding with detail extraction")
            # print("Lets get details about the domain")
            domain_details = fetch_details(domain)
            parse_domain_details(domain_details)
            # print("lets confirm Users existance")
            if check_user(username, domain):
                fetch_user_details(username, domain)
            else:
                print("[❌] User Doesnt Exists")
        else:
            print("[⛔️] Not a fediverse entity")
    elif args.update:
        print("lets check if update is needed: new file to be fetched if last update was more then 6 hours older")
        if is_file_older_than("nodes.json", timedelta(hours=10)):
            node_list = requests.get(nodelist_url, headers=headers, timeout=2)
            if node_list.status_code == 200:
                open('nodes.json', 'w').write(node_list.text)
            else:
                print("[⛔] Error while updating file")
    elif args.search:
        name_hunt = args.search
        print("Lets hunt for the username " + name_hunt)
        hunt_name(name_hunt)
    else:
        parser.print_usage()

    finish = time.perf_counter()
    print(f"Finished in {round(finish - start, 2)} seconds")


if __name__ == "__main__":
    main()
