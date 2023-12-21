import hashlib
import hmac
import base64
from time import time

#
# Coturn auth 
#
# https://github.com/coturn/coturn/blob/master/README.turnserver
#
# --use-auth-secret	TURN REST API flag.
# Flag that sets a special WebRTC authorization option
#		that is based upon authentication secret. The feature purpose
#		is to support "TURN Server REST API" as described in
#		the TURN REST API section below.
#		This option uses timestamp as part of combined username:
#		usercombo -> "timestamp:username",
#		turn user -> usercombo,
#		turn password -> base64(hmac(input_buffer = usercombo, key = shared-secret)).
#
# Look at
# https://docs.bigbluebutton.org/administration/turn-server/#test-your-turn-server

def create_coturn_credentials( coturn_static_auth_secret:str, ttl:int=3600 )->tuple:
  timestamp = int(time()) + ttl
  # username = str(timestamp) + ':' + user
  username = str(timestamp)
  dig = hmac.new(coturn_static_auth_secret.encode(), username.encode(), hashlib.sha1).digest()
  password = base64.b64encode(dig).decode()
  return (username,password)
