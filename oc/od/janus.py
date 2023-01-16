import requests
import json
import string
import random
import threading
import logging
import oc.logging
import hashlib


logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class janusclient( object ):

    def __init__(self, node, timeout=3 ):
        self.session = {    "session_id": None,
                            "handle_id": None,
                            "ports": None,
                            "hosts": None }
        
        # The connect timeout is the number of seconds Requests will wait for your client to establish 
        # a connection to a remote machine (corresponding to the connect()) call on the socket. 
        # It’s a good practice to set connect timeouts to slightly larger than a multiple of 3, 
        # which is the default TCP packet retransmission window.
        # Once your client has connected to the server and sent the HTTP request, 
        # the read timeout is the number of seconds the client will wait for the server to send a response. 
        self.timeout = timeout

        # desktop rtp stream default config
        # read https://janus.conf.meetecho.com/docs/streaming.html
        # read https://en.wikipedia.org/wiki/RTP_payload_formats
        # by default abcdesktop use 
        # 8	PCMA	audio	1	8000	any	20	ITU-T G.711 PCM A-Law audio 64 kbit/s	RFC 3551
        # audio RTP payload type for example 8
        self.audiopt     = node.get('audiopt', 8)
        # audiortpmap = RTP map of the audio codec (e.g., PCMA/8000)
        self.audiortpmap = node.get('audiortpmap', 'PCMA/8000' )

        # Janus config
        self.MAX_RETRY_CREATE_STREAM = 5
        self.janus_schema   = node.get('schema', 'http')
        self.janus_host     = node.get('host', 'localhost')
        self.janus_hostip   = node.get('hostip', 'localhost')
        self.janus_port     = node.get('port', 8088)
        self.janus_apisecret = node.get('apisecret', 'janusrocks')
        self.janus_adminkey  = node.get('adminkey',  'supersecret')
        self.janus_adminsecret = node.get('adminsecret',  'supersecret')
        self.janus_startport = node.get('startport', 5100 )
        self.janus_url = self.janus_schema + '://' + self.janus_hostip + ':' + str(self.janus_port) + '/janus'
        self.janus_admin_base_path = node.get('admin_base_path','/admin')
        self.admin_janus_schema = node.get('admin_janus_schema', 'https')
        self.admin_secure_port =  node.get('admin_secure_port',7889)
        self.salt_encoded = node.get('token_salt','dummysalt').encode()
        self.admin_janus_url = self.admin_janus_schema + '://' + self.janus_host + ':' + str(self.admin_secure_port) + self.janus_admin_base_path
        self.token = None
        self.transaction = janusclient.randomStringwithDigitsAndSymbols()

    @staticmethod
    def randomStringwithDigitsAndSymbols(stringLength=10):
        ''' Generate a random string of letters, digits and special characters '''
        password_characters = string.ascii_letters + string.digits 
        return ''.join(random.choice(password_characters) for i in range(stringLength))

    def mktoken( self, token ):
        h = hashlib.new('sha256')
        h.update(token.encode())
        h.update(self.salt_encoded)
        new_token = h.hexdigest()
        return new_token


    # Request JSON POST
    def mypost(self, url, json_v):
        return requests.request("POST", url, data=json.dumps(json_v), headers={"Content-Type": "application/json"}, timeout=self.timeout)


    def janus_cmd(self, cmd, cond=False, action=lambda x: x, endpoint=""):
        if cond:
            raise ValueError( 'Misplaced call to janus gateway')
        else:
            r = self.mypost(self.janus_url + endpoint, cmd)
            if isinstance(r, requests.models.Response) and r.ok :
                j = r.json()
                self.logger.debug(json.dumps(j, indent=4, separators=(',', ': ')))
                return action(j)
            else:
                error_message =  'janus request %s post %s return %s' % (str(self.janus_url) + str(endpoint), str(cmd), str(r)  )
                self.logger.error( error_message )
                raise ValueError( 'Error call to janus gateway %s ', error_message )

    def janus_admin_cmd(self, cmd, cond=False, action=lambda x: x ):
        if cond:
            raise ValueError( 'Misplaced call to janus gateway')
        else:
            r = self.mypost(self.admin_janus_url, cmd)
            if isinstance(r, requests.models.Response) and r.ok :
                j = r.json()
                self.logger.debug(json.dumps(j, indent=4, separators=(',', ': ')))
                return action(j)
            else:
                error_message =  'janus request %s post %s return %s' % (str(self.admin_janus_url), str(cmd), str(r)  )
                self.logger.error( error_message )
                raise ValueError( 'Error call to janus gateway %s ', error_message )



    def ping( self ):
        pong = False
        def helper(j):
            return j.get('janus') == "pong"

        json_create = { "janus":       "ping",
                        "apisecret":   self.janus_apisecret,
                        "transaction": self.transaction
                    }
        try:
            pong = self.janus_cmd(json_create, action=helper)
        except Exception as e:
            self.logger.error( e )
        return pong

    def add_token( self, token ):
        add = None
        def helper(j):
            # 'janus':'success'
            return j.get('janus') == 'success'

        new_token = self.mktoken( token )

        json_create = { "janus":       "add_token",
                        "admin_secret":   self.janus_adminsecret,
                        "transaction": self.transaction,
                        "token": new_token
                    }
        try:
            add = self.janus_admin_cmd(json_create, action=helper)
            if add is True:
                self.token = new_token
        except Exception as e:
            self.logger.error( e )
        return add

    def remove_token( self  ):
        remove = None
        def helper(j):
            return j.get('janus') == 'success'

        json_remove = { "janus":            "remove_token",
                        "admin_secret":     self.janus_adminsecret,
                        "transaction":      self.transaction,
                        "token":            self.token
                    }
        try:
            remove = self.janus_admin_cmd(json_remove, action=helper)
        except Exception as e:
            self.logger.error( e )
        return remove

    def greet(self):     
        def helper(j):
            self.session["session_id"] = j["data"]["id"]
            return self.session["session_id"]

        json_create = { "janus":        "create",
                        "apisecret":    self.janus_apisecret,
                        "transaction":  self.transaction,
                        "token":        self.token
                    }
        return self.janus_cmd(json_create, action=helper)

    def attach(self, plugin="janus.plugin.streaming"):

        def helper(j):
            self.session["handle_id"] = j["data"]["id"]
            return self.session["handle_id"]

        json_attach = { "janus":        "attach",
                        "plugin":       plugin,
                        "apisecret":    self.janus_apisecret, 
                        "transaction":  self.transaction,
                        "token":        self.token }

        return self.janus_cmd(json_attach,
                not self.session["session_id"],
                helper,
                endpoint="/" + str(self.session["session_id"]))

    def list(self, id=None, action=lambda x: x,):
        
        body = not id and {"request": "list"} or {"request": "list", "id": id}
        jsondata = {"janus": "message",
                    "transaction": self.transaction,
                    "body": body,
                    "apisecret": self.janus_apisecret,
                    "token":        self.token }
        return self.janus_cmd(jsondata,
                not self.session["session_id"] or not self.session["handle_id"],
                action,
                endpoint="/" + str(self.session["session_id"]) + "/" + str(self.session["handle_id"]))


    def list_maxid(self, action=lambda x: x):
        
        def helper(j):
            currentid = None
            try:
                datalist = j["plugindata"]["data"]["list"]
                currentid = 0
                for e in datalist:
                    if e['id'] > currentid:
                        currentid = e['id']
            except Exception:   
                pass
            return currentid
           
        return self.list( action=helper )

    def find( self, description ):

        def helper(j):
            try:
                datalist = j["plugindata"]["data"]["list"]
                for e in datalist:
                    if e['description'] == description:
                        return self.info( e['id'] )
            except Exception:
                pass
            return None

        return self.list( action=helper )


    def create( self, janusid, description = "desktop pulseaudio stream"):
        audioport = self.janus_startport + janusid
        pin = self.randomStringwithDigitsAndSymbols()
        def helper(j):
            return j["plugindata"]["data"]

        return self.janus_cmd(
            {   "janus": "message",
                "transaction": self.transaction,
                "apisecret": self.janus_apisecret,
                "token":        self.token,
                "body": {
                    "request": "create",
                    "id": janusid,
                    "type": "rtp",
                            "audio": True,
                            "video": False,
                            "description": description,
                            "audioport": audioport,
                            "audiopt": self.audiopt,
                            "audiortpmap": self.audiortpmap,
                            "admin_key": self.janus_adminkey,
                            "audioiface": self.janus_hostip,
                            "pin": pin
                }
            },
            not self.session["session_id"] or not self.session["handle_id"],
            helper,
            endpoint="/" + str(self.session["session_id"]) + "/" + str(self.session["handle_id"])
        )

    def info( self, janusid):
        def helper(j):
            json_data = None
            try:
                json_data = j["plugindata"]["data"]["info"]
                json_data['host']   = self.janus_host
                json_data['hostip'] = self.janus_hostip
                json_data['token']  = self.token
            except Exception as e:
                self.logger.error( e )
            return json_data


        message_dict =  {   "janus": "message",
                            "token": self.token,
                            "transaction": self.transaction,
                            "apisecret": self.janus_apisecret,
                            "body": {
                                "request": "info",
                                "id": janusid
                            }
        }
        return self.janus_cmd(
            message_dict,
            not self.session["session_id"] or not self.session["handle_id"],
            helper,
            endpoint="/" + str(self.session["session_id"]) + "/" + str(self.session["handle_id"])
        )

    def destroy(self, janusid):

        def helper(j):
            return j.get('janus') == 'success'

        destroy_dict = {    "janus":        "message",
                            "transaction":  self.transaction,
                            "token":        self.token,
                            "body": {   "request": "destroy",
                                        "id": janusid,
                                        "admin_key": self.janus_adminkey
                            }
        }
        return self.janus_cmd(  destroy_dict, 
                                not self.session["session_id"] or not self.session["handle_id"],
                                action=helper,
                                endpoint="/" + str(self.session["session_id"]) + "/" + str(self.session["handle_id"]))

   
   
    def get_stream(self, pod_name ):
        if self.token is None:
            self.add_token( token=pod_name )

        self.greet()
        self.attach()
        n = 0
        while(  n < self.MAX_RETRY_CREATE_STREAM ):
            janusid = self.list_maxid() 
            if type( janusid ) is not int:
                raise ValueError( 'invalid maxid value' )
            janusid = janusid + 1
            json_data = self.create( janusid, description=pod_name )
            # if a conflict error occurs
            if json_data.get( 'error_code' ) == 456:
                # "A stream with the provided ID already exists"
                continue
            if json_data.get( 'streaming') == 'created':
                json_data['host'] = self.janus_host
                return json_data
            n = n + 1
          
@oc.logging.with_logger()
class ODJanusCluster():

    def __init__(self, server={}):
        self.nodes = server

    def add_node(self, node ):
        if type(node) is not dict:
            raise ValueError( 'Invalid node type')
        self.nodes[ node['host'] ]  = node

    def list_node( self ):
        return self.nodes

    def remove_node(self, host):
        del self.nodes[ host ]

    def givemeanode( self ):
        keys = list(self.nodes.keys())
        random.seed()
        while( len(keys) > 0 ):
            i = random.randint(0, len(keys)-1)
            node = self.nodes[ keys[i] ]
            # Check if node is up
            janus = janusclient( node )
            ping = janus.ping()
            if ping is True:
                return node
            else:
                # remove not reponsing entry
                self.logger.info('Removing not responding gateway %s', keys[i] )
                del keys[i]
        return None


    def create_stream( self, pod_name ):
        # create a new stream
        # find a janus server
        node = self.givemeanode()
        if node is None:
            raise ValueError( 'Can not find running janus gateway') 
        
        # create a janus client
        janus = janusclient( node )
        # create a streaming entry
        stream = janus.get_stream( pod_name )
        info = janus.info( stream['stream']['id'] )
        return info

    @staticmethod
    def thread_get_info( node, pod_name, results, i ):
        janus = janusclient( node )
        try:
            janus.add_token( token=pod_name )
            janus.greet()
            janus.attach()
            results[i] = janus.find( description=pod_name )
        except Exception as e:
            logger.error('not responding gateway %s %s', node.get('host'), str(e) )
            results[i] = None

    def find_stream( self, pod_name, timeout=3 ):
        self.logger.debug('')
        if type(self.nodes) is not dict:
            return None

        keys    = list(self.nodes.keys())
        results = {}
        threads = {}

        # look for the pod_name on each janus gateway server
        for i in keys :            
            # check if stream info exist
            threads[i] = threading.Thread(target=ODJanusCluster.thread_get_info, args=(self.nodes[i], pod_name, results, i))
            threads[i].start()

        for i in threads:
            threads[i].join( timeout=timeout )
            if  threads[i].isAlive():
                # timeout expired
                pass

        # check if data has been found
        for i in results:
            if results[i] is not None:
                return results[i]
        return None        


    def get_stream( self, pod_name ):
        """[get_stream]

        Args:
            pod_name ([str]): create or return a strean if exixts

        Returns:
            [dict]: [stream dict description]
        """
        self.logger.debug('')
        # look for a stream
        if type(pod_name) is not str:
            self.logger.error( 'invalid stream name type')
            return None

        stream = self.find_stream( pod_name )
        if stream is None:
            self.logger.debug( 'stream entry %s does not exist, create a new one', pod_name )
            # not found, create it
            stream = self.create_stream( pod_name )
            self.logger.debug( 'new stream create' )
        # self.logger.debug( 'get_stream return %s ', stream )
        return stream

    def destroy_stream( self, pod_name ):
        self.logger.debug('')
        bReturn = False
        if type(pod_name) is not str:
            self.logger.error( 'invalid stream name type')
            return None

        stream = self.find_stream( pod_name )
        if isinstance(stream, dict):
            node = self.nodes.get( stream['host'] )
            if node is None:
                raise ValueError('Invalid node host')
            # create a janus client
            janus = janusclient( node )
            janus.add_token( token=pod_name )
            janus.greet()
            janus.attach()
            # remove the stream id
            if janus.destroy( stream.get('id') ) is True: 
                # remove the token
                if janus.remove_token() is True:
                    bReturn = True
        return bReturn
