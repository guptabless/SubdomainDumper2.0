import requests
import json
import bcolors
import sys,argparse

print("-----------------------------------------------")
print("Check Sub-domain of a Website from VirusTotal")
print("Code By : NG")
print("Usage:  python VirusTotal.py -u <input_url>")
print("Enter the URL without https:// or http://")
print("-----------------------------------------------")

def banner():
    print("""
    
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
─██████──██████─██████████─████████████████───██████──██████─██████████████─██████████████─██████████████─██████████████─██████████████─██████─────────
─██░░██──██░░██─██░░░░░░██─██░░░░░░░░░░░░██───██░░██──██░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░██─────────
─██░░██──██░░██─████░░████─██░░████████░░██───██░░██──██░░██─██░░██████████─██████░░██████─██░░██████░░██─██████░░██████─██░░██████░░██─██░░██─────────
─██░░██──██░░██───██░░██───██░░██────██░░██───██░░██──██░░██─██░░██─────────────██░░██─────██░░██──██░░██─────██░░██─────██░░██──██░░██─██░░██─────────
─██░░██──██░░██───██░░██───██░░████████░░██───██░░██──██░░██─██░░██████████─────██░░██─────██░░██──██░░██─────██░░██─────██░░██████░░██─██░░██─────────
─██░░██──██░░██───██░░██───██░░░░░░░░░░░░██───██░░██──██░░██─██░░░░░░░░░░██─────██░░██─────██░░██──██░░██─────██░░██─────██░░░░░░░░░░██─██░░██─────────
─██░░██──██░░██───██░░██───██░░██████░░████───██░░██──██░░██─██████████░░██─────██░░██─────██░░██──██░░██─────██░░██─────██░░██████░░██─██░░██─────────
─██░░░░██░░░░██───██░░██───██░░██──██░░██─────██░░██──██░░██─────────██░░██─────██░░██─────██░░██──██░░██─────██░░██─────██░░██──██░░██─██░░██─────────
─████░░░░░░████─████░░████─██░░██──██░░██████─██░░██████░░██─██████████░░██─────██░░██─────██░░██████░░██─────██░░██─────██░░██──██░░██─██░░██████████─
───████░░████───██░░░░░░██─██░░██──██░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─────██░░██─────██░░░░░░░░░░██─────██░░██─────██░░██──██░░██─██░░░░░░░░░░██─
─────██████─────██████████─██████──██████████─██████████████─██████████████─────██████─────██████████████─────██████─────██████──██████─██████████████─
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
                                                                                                                        code by NG        

    """)

if len(sys.argv) > 1:
    banner()
    if (sys.argv[1] == '-d'):
        try:
            input_site = sys.argv[2]
            parser = argparse.ArgumentParser()
            parser.add_argument("-d", required=True)
            args = parser.parse_args()

            url = 'https://www.virustotal.com/ui/domains/'+input_site+'/subdomains'
            request_input= requests.get(url)

            print(bcolors.BLUE + "Found Sub-domain List:")
            try:
                json_input = json.loads(request_input.text)
                res1 = json_input["data"][1]["id"]
                http_res1 = "https://" + res1
                print(bcolors.OKMSG + json_input["data"][1]["id"]+ bcolors.BLUE + 'This domain is reachable' )
            except:
                print(bcolors.ERR + 'Domain',http_res1 , 'This domain is not reachable')

            try:
                res2 = json_input["data"][2]["id"]
                http_res2 = "https://" + res2
                print(bcolors.OKMSG + json_input["data"][2]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res2,'This domain is not reachable')

            try:
                res3 = json_input["data"][3]["id"]
                http_res3 = "https://" + res3
                print(bcolors.OKMSG + json_input["data"][3]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res3,'This domain is not reachable')

            try:
                res4 = json_input["data"][4]["id"]
                http_res4 = "https://" + res4
                print(bcolors.OKMSG + json_input["data"][4]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res4,'This domain is not reachable')

            try:
                res5 = json_input["data"][5]["id"]
                http_res5 = "https://" + res5
                print(bcolors.OKMSG + json_input["data"][5]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res5,'This domain is not reachable')

            try:
                res6 = json_input["data"][6]["id"]
                http_res6 = "https://" + res6
                print(bcolors.OKMSG + json_input["data"][6]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res6, 'This domain is not reachable')

            try:
                res7 = json_input["data"][7]["id"]
                http_res7 = "https://" + res7
                print(bcolors.OKMSG + json_input["data"][7]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res7, 'This domain is not reachable')

            try:
                res8 = json_input["data"][8]["id"]
                http_res8 = "https://" + res8
                print(bcolors.OKMSG + json_input["data"][8]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res8, 'This domain is not reachable')

            try:
                res9 = json_input["data"][9]["id"]
                http_res9 = "https://" + res9
                print(bcolors.OKMSG + json_input["data"][9]["id"]+ bcolors.BLUE + 'This domain is not reachable')
            except:
                print(bcolors.ERR + 'Domain', http_res9, 'This domain is not reachable')
        except:
            print(bcolors.ERR + 'please enter domain name with -d option' )

    elif((sys.argv[1] == '-h') | (sys.argv[1] == '--help')):
            print(bcolors.BOLD + 'usage: VirusTotal.py [-h] -d DOMAIN' '\n' 'OPTIONS:' '\n' '-h,--help    '
                             'show this help message and exit' '\n''-d Domain,   --domain Domain')
else:
    banner()
    print(bcolors.ERR + 'Please select option from -d or -h, with a valid domain name')



