import requests
import logging
import oc.logging


logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class postponeapp( object ):

    def __init__(self, user, auth ):
        self.timeout = timeout


    def post(self, user, auth, url ):
        
        return requests.request( "POST", url, data=json.dumps(json_v), headers={"Content-Type": "application/json"}, timeout=self.timeout)
