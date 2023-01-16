#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

###
# AES Cipher to build a token


class AESCipher:
    def __init__(self, key=None):
        self.randomkey = 4096
        self.BS = 16
        self.pad = lambda s: s + (self.BS - len(s) %
                                  self.BS) * chr(self.BS - len(s) %
                                                 self.BS)
        self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        if key is None:
            key = Random.new().read(self.randomkey)
        self.key = hashlib.md5(key).hexdigest()[:self.BS]

    def encrypt(self, raw):
        raw = self.pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.urlsafe_b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.urlsafe_b64decode(enc)
        iv = enc[:self.BS]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[self.BS:]))
