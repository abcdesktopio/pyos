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

import smtplib
import json
import time

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from string import Template
from oc.cipher import *


class MailConfig(object):

    def __init__(
            self,
            protocol,
            serverfqdn,
            serverport,
            login,
            fromaddr,
            password,
            subject,
            mailfile):
        self.lastErrorMessage = None
        self.protocol = protocol
        self.serverfqdn = serverfqdn
        self.fromaddr = fromaddr
        self.password = password
        self.serverport = serverport
        self.subject = subject
        self.login = login
        self.mailfile = mailfile


class Mail(object):

    def __init__(self, conf):
        self.conf = conf
        self.lastErrorMessage = None

    def createmailtoken(self, email, share, environment_id, user_id, hostname):
        jsonToken = {}
        jsonToken['createtime'] = time.time()
        jsonToken['share'] = share
        jsonToken['user_id'] = user_id
        jsonToken['environment_id'] = environment_id
        jsonToken['hostname'] = hostname

        strToken = json.dumps(jsonToken)
        aes = AESCipher(email.encode('utf-8'))
        crypto = aes.encrypt(strToken)
        return crypto.decode('utf-8')

    def decodemailtoken(self, email, crypto):
        aes = AESCipher(email.encode('utf-8'))
        ecrypto = crypto.encode('utf-8')
        token = aes.decrypt(ecrypto)
        jsonToken = None
        try:
            jsonToken = json.loads(token)
        except ValueError as e:
            self.lastErrorMessage = 'invalid token'
            return None

        createtime = jsonToken.get('createtime', None)
        if createtime is None:
            self.lastErrorMessage = 'invalid token expired time value'
            return None

        deltatime = time.time() - createtime
        # Permit 1 hour for the token
        if deltatime < 0 or \
                deltatime > 3600:
            self.lastErrorMessage = 'token expired'
            return None
        if jsonToken.get('environment_id', None) is None:
            self.lastErrorMessage = 'invalid token format (environement_id)'
            return None
        if jsonToken.get('hostname', None) is None:
            self.lastErrorMessage = 'invalid token format (hostname)'
            return None
        if jsonToken.get('user_id', None) is None:
            self.lastErrorMessage = 'invalid token format (user_id)'
            return None
        return jsonToken

    def getHTMLBody(self, buser, urlweb, urltoken, ua, ipuser):

        src = None
        try:
            filein = open(self.conf.mailfile)
            src = Template(filein.read())
            filein.close()
        except Exception as e:
            return None

        defaultuser = 'A user share with you'
        if buser is None:
            buser = defaultuser

        encodedurltoken = urltoken.encode('utf-8')
        try:
            # force convert utf8 to python string
            encodeduser = buser.encode('utf-8')
        except e:
            encodeduser = unicode(defaultuser, 'utf-8')

        d = {'buser': buser,
             'urlweb': urlweb,
             'blink': urltoken,
             'date': time.strftime('%d/%m/%y %H:%M', time.localtime()),
             # cherrypy.request.headers.get( 'HTTP_USER_AGENT', 'not defined'),
             'ua': ua,
             # cherrypy.request.headers.get('X-Forwarded-For', 'not defined change nginx.conf to set X-Forwarded-For header')
             'ipuser': ipuser
             }

        '''
        <div id="support">
                <h3 style="text-align: center;">Support Ticket</h3>
                <p>Username : $buser</p>
                <p>Date : $date</p>
                <p>Container ID : $cid </p>
                <p>IP source : $ipuser </p>
                <p>User Agent : $ua </p>
                <p>Name cluster : $clustername</p>
                <div style="text-align: right;padding-right: 10px;"><a style="color: white;" href="$blink">Remote access</a></div>
        </div>
        '''
        result = src.substitute(d)
        return result

    def getTEXTBody(self, buser, urltoken):
        result = None
        try:
            filein = open('mailshare.template.txt')
            src = Template(filein.read())
            d = {'buser': buser, 'blink': urltoken}
            result = src.substitute(d)
            filein.close()
        except Exception as e:
            self.lastErrorMessage = str(e)
            return None
        return result

    def sendmail(self, targetemail, urlweb, urltoken, buser, ua, ipuser):
        bReturn = False
        try:
            # build data messsage
            msg = MIMEMultipart()
            msg['Subject'] = self.conf.subject
            msg['To'] = targetemail
            bodyhtml = self.getHTMLBody(buser, urlweb, urltoken, ua, ipuser)
            msg.attach(MIMEText(bodyhtml, 'html'))

            # connect to server
            server = smtplib.SMTP()
            server.connect(self.conf.serverfqdn, self.conf.serverport)
            server.ehlo()
            if self.conf.protocol == 'tls':
                server.starttls()
            server.login(self.conf.login, self.conf.password)
            server.sendmail(self.conf.fromaddr, targetemail, msg.as_string())
            server.quit()
            bReturn = True
        except Exception as e:
            if self.lastErrorMessage is None:
                self.lastErrorMessage = str(e)
        return bReturn
