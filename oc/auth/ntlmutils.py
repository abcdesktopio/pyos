import string
import des
import hashlib
import hmac
import re
import binascii

# from
# https://github.com/mullender/python-ntlm/blob/master/python26/ntlm/ntlm.py


def create_LM_hashed_password_v1(passwd):
    "setup LanManager password"
    "create LanManager hashed password"
    # if the passwd provided is already a hash, we just return the first half
    if re.match(r'^[\w]{32}:[\w]{32}$', passwd):
        return binascii.unhexlify(passwd.split(':')[0])

    # fix the password length to 14 bytes
    passwd = string.upper(passwd)
    lm_pw = passwd + '\0' * (14 - len(passwd))
    lm_pw = passwd[0:14]

    # do hash
    magic_str = "KGS!@#$%"  # page 57 in [MS-NLMP]

    res = ''
    dobj = des.DES(lm_pw[0:7])
    res = res + dobj.encrypt(magic_str)

    dobj = des.DES(lm_pw[7:14])
    res = res + dobj.encrypt(magic_str)

    return res


def create_NT_hashed_password_v1(passwd, user=None, domain=None):
    "create NT hashed password"
    # if the passwd provided is already a hash, we just return the second half
    if re.match(r'^[\w]{32}:[\w]{32}$', passwd):
        return binascii.unhexlify(passwd.split(':')[1])

    digest = hashlib.new('md4', passwd.encode('utf-16le')).digest()
    return digest

def create_NT_hashed_password_v2(passwd, user, domain):
    "create NT hashed password"
    digest = create_NT_hashed_password_v1(passwd)
    return hmac.new( digest,(user.upper() + domain).encode('utf-16le')).digest()