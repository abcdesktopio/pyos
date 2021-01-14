import logging
import oc.logging
import requests
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class lyncconfig(object):
    def __init__(
            self,
            server,
            domain,
            checkAttributsOnDomain,
            protocol='https',
            autodiscoverurl='/autodiscover/autodiscoverservice.svc/root'):
        self.server = server
        self.domain = domain
        self.checkAttributsOnDomain = checkAttributsOnDomain
        self.autodiscoverurl = protocol + '://' + server + autodiscoverurl
        self.useroauthurl = None
        self.httptimeout = 60  # 60 seconds

        # remove insecure message warning
        # THIS IS BAD !!!!
        # Only for test
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def isSipAddressEnable(self, proxyAddress):
        self.logger.info('type proxyAddress is %s', type(proxyAddress)) 
        if isinstance(proxyAddress, bytes):
           proxyAddress = proxyAddress.decode('utf-8')
        if isinstance(proxyAddress, str):
            return proxyAddress.startswith('sip:')
        return False

    def isSipAddressesEnable(self, proxyAddresses):
        if isinstance(proxyAddresses, str):
            return self.isSipAddressEnable(proxyAddresses)
        if isinstance(proxyAddresses, list):
            for addr in proxyAddresses:
                b = self.isSipAddressEnable(addr)
                if b:
                    return b
        return False

    def get_checkAttributsOnDomain(self):
        return self.checkAttributsOnDomain

    def autodiscover(self):
        bReturn = False
        try:
            self.logger.debug(str(self.autodiscoverurl))
            r = requests.get( self.autodiscoverurl, verify=False, timeout=self.httptimeout)
            jsonautodiscover = r.json()
            self.useroauthurl = jsonautodiscover['_links']['user']['href']
            self.domain = urlparse(self.useroauthurl)
            bReturn = True
        except Exception as e:
            message = str(e)
            if hasattr(e, 'reason'):
                message = 'lyncconfig:autodiscover ' + str(self.autodiscoverurl) + ' can not be reach: ' + str(e.reason)
            elif hasattr(e, 'code'):
                message = 'lyncconfig:autodiscover the server ' + str(self.autodiscoverurl) + ' couldn\'t fulfill the request.'
            self.logger.error(message)
        return bReturn

    def extractAuthURL(self, str):
        start = str.find('MsRtcOAuth')
        q1 = str.find('"', start)
        q2 = str.find('"', q1 + 1)
        if q1 == -1 or q2 == -1:
            raise Exception("cannot find MsRtcOAuth href string")
        return str[q1 + 1:q2]

    def msrtcoauth(self):
        bReturn = False
        if self.useroauthurl is None:
            return False
        try:
            #  expect a 401/address from oauth server
            # self.useroauthurl = self.useroauthurl + u"?originalDomain=" + self.domain
            # self.log( 'lyncconfig:msrtcoauth ' + self.useroauthurl )
            r = requests.get(
                self.useroauthurl,
                verify=False,
                timeout=self.httptimeout)
            self.msrtcoauthurl = self.extractAuthURL(
                r.headers['www-authenticate'])
            self.logger.debug(' msrtcoauth is ' + self.msrtcoauthurl)
            bReturn = True
        except Exception as e:
            message = str(e)
            if hasattr(e, 'reason'):
                message = str(self.msrtcoauth) + ' can not be reach: ' + str(e.reason)
            elif hasattr(e, 'code'):
                message = 'The server ' + str(self.msrtcoauth) + ' couldn\'t fulfill the request.'
            self.logger.error(message)
        return bReturn

    def init(self):
        if not self.autodiscover():
            return False
        if not self.msrtcoauth():
            return False
        return True

    def show(self):
        self.logger.debug('[lync:useroauthurl] ' + str(self.useroauthurl))
        self.logger.debug('[lync:msrtcoauthurl] ' + str(self.msrtcoauthurl))


@oc.logging.with_logger()
class lync(object):

    def __init__(self, lyncconf):
        self.conf = lyncconf

    def auth(self, username, password):

        result = {}
        message = None

        if self.conf.useroauthurl is None or self.conf.msrtcoauthurl is None:
            message = 'lync:auth error url invalid configuration '
            self.logger.error(message)
            return (None, message)

        try:
            data = { 'grant_type': 'password', 'username': username, 'password': password}
            r = requests.post(
                self.conf.msrtcoauthurl,
                data=data,
                verify=False,
                timeout=self.conf.httptimeout)
            self.logger.debug(str(r))
            r.raise_for_status()
            access_token = r.json()
        except Exception as e:
            message = 'lync:auth STEP(1) error try to obtain access token, url access error ' + \
                str(self.conf.msrtcoauthurl) + ' ' + str(e)
            self.logger.error(message)
            return (None, message)

        try:
            auth_headers = {
                'Authorization': "{0} {1}".format(
                    access_token['token_type'],
                    access_token['access_token'])}
            r = requests.get(
                self.conf.useroauthurl,
                headers=auth_headers,
                verify=False,
                timeout=self.conf.httptimeout)
            # logger.info( self.conf.useroauthurl )
            # logger.info( str(r) )
            r.raise_for_status()
            # myjson = r.json()
            # pool_url :
            # https://FQDN/Autodiscover/AutodiscoverService.svc/root/user
            pool_url = r.json()['_links']['self']['href']
            pool_fqdn = urlparse(pool_url).netloc
            parseauth_url = urlparse(self.conf.msrtcoauthurl)
            self.logger.debug('pool_url = %s', pool_url)
        except Exception as e:
            message = 'lync:auth STEP(2) error: try to obtain pool_url, from url ' + str(self.conf.useroauthurl) + ' ' + str(e)
            self.logger.error(message)
            return (None, message)

        try:
            # connection to the correct pool
            authpool_url = None
            authpool_url = parseauth_url.scheme + '://' + pool_fqdn + parseauth_url.path
            self.logger.info(authpool_url)
            # retry login with the correct pool url
            data = { 'grant_type': 'password', 'username': username, 'password': password}
            r = requests.post(authpool_url, data=data, verify=False)
            # logger.info( str(r) )
            r.raise_for_status()
            access_token = r.json()
        except Exception as e:
            if authpool_url is None:
                authpool_url = 'undefined'
            message = 'lync:auth STEP(3) error url access error to ' + str(authpool_url) + ' ' + str(e)
            self.logger.error(message)
            return (None, message)

        try:
            # get _links
            userauthpool_url = None
            auth_headers = {
                'Authorization': "{0} {1}".format(
                    access_token['token_type'],
                    access_token['access_token'])}
            # logger.info('user pool_url = ' + pool_url)
            parsepool_url = urlparse(pool_url)
            pooluseroauthurl = urlparse(self.conf.useroauthurl)
            userauthpool_url = parsepool_url.scheme + '://' + \
                parsepool_url.netloc + pooluseroauthurl.path
            # logger.info('userauthpool_url=' + userauthpool_url)
            r = requests.get(
                userauthpool_url,
                headers=auth_headers,
                verify=False,
                timeout=self.conf.httptimeout)
            r.raise_for_status()
            jsonlinks = r.json()
            result['access_token'] = access_token
            result['_links'] = jsonlinks['_links']
        except Exception as e:
            if userauthpool_url is None:
                userauthpool_url = 'undefined'
            message = 'lync:auth STEP(4) error url access error ' + str(userauthpool_url) + ' ' + str(e)
            self.logger.error(message)
            return (None, message)

        return (result, message)
