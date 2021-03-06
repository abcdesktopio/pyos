import docker
import logging 
import threading
import logging
import oc.logging

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODDockerWatcher:

    def __init__(self):
        self.abcnetworks = {}
        client = oc.od.infra.ODInfra().getdockerClient()

        # list all networks
        local_networks = client.networks.list( filters={'label': 'oc.type=app'} )
        for mynetwork in local_networks:
            self.abcnetworks[ mynetwork.id ] = mynetwork
        client.close()

    def event_image( self, client, event ):
        logger.debug('new image event from docker event %s', event)
        event_action = event.get('Action') 
        event_attributes = event.get('Actor').get('Attributes')
        if event_action == 'pull' or event_action == 'tag':
            image_name = event_attributes.get('name')
            if event_attributes.get('oc.type') == 'app' and image_name is not None :
                newapp = oc.od.services.services.apps.add_image( image_name )
                if (newapp):
                    self.logger.debug( 'new image added %s', newapp )
                else:
                    self.logger.debug( 'Skipping image %s', newapp )
        if event_action == 'delete': 
            # delete is after event_action == 'untag' 
            # name is the image id
            # example
            # 2021-03-01 09:54:52 watcher [INFO   ] oc.od.watcher.event_image:anonymous new image event from docker event 
            # {'status': 'delete', 'id': 'sha256:f61fb567da32206d0b9ba479683df5ceadc61998680bbfd0650a0c9e7be0133b', 'Type': 'image', 'Action': 'delete', 
            # 'Actor': {    'ID': 'sha256:f61fb567da32206d0b9ba479683df5ceadc61998680bbfd0650a0c9e7be0133b', 
            #               'Attributes': {'name': 'sha256:f61fb567da32206d0b9ba479683df5ceadc61998680bbfd0650a0c9e7be0133b'}}, 
            # 'scope': 'local', 
            # 'time': 1614588892, 
            # 'timeNano': 1614588892647421832}
            image_id = event.get('id')
            oc.od.services.services.apps.del_image( image_sha_id=image_id )

    def event_network( self, client, event ):
        self.logger.debug('new network event from docker event %s', event)
        event_action = event.get('Action') 
        if event_action == 'create' :
            network_id = event.get('Actor').get('ID')
            new_network = client.networks.get(network_id)
            network_labels = new_network.attrs.get('Labels')
            if network_labels.get('oc.type') == 'app':
                self.abcnetworks[ network_id ] = new_network
                self.logger.info( 'add new network in watching dict %s', network_id )

        if event_action == 'destroy' :
            network_id = event.get('Actor').get('ID')
            if self.abcnetworks.get( network_id ):
                del self.abcnetworks[ network_id ]
                self.logger.info( 'remove network in watching dict %s', network_id )

        if event_action == 'disconnect' :
            container_id = event.get('Actor').get('Attributes').get('container')
            oc.od.composer.detach_container_from_network( container_id )

    def event_oom( self, client, event ):
        self.logger.debug('new oom event from docker event %s', event)
        try:
            attributes = event.get('Actor').get('Attributes')
            access_userid   = attributes.get('access_userid')
            access_type     = attributes.get('access_type')
            name            = attributes.get('oc.name')
            # skip not abcdeskop container notification 
            if access_userid is None or  access_type is None or name is None :
                return
            message = "Out of memory for application {}".format(  name )
            data = { 'status':  event.get('status'), 
                     'message': message, 
                     'icon':    attributes.get('oc.icon'), 
                     'image':   attributes.get('image'), 
                     'launch':  attributes.get('oc.launch'), 
                     'name':    name }

            oc.od.composer.notify_user( access_userid=access_userid,
                                        access_type=access_type, 
                                        method='container', 
                                        data=data )

        except Exception as e:
            self.logger.error(str(e))

    def event_die( self, client, event ):
        self.logger.debug('new die event from docker event %s', event)
        try:
            attributes = event.get('Actor').get('Attributes')
            access_userid   = attributes.get('access_userid')
            access_type     = attributes.get('access_type')
            name            = attributes.get('oc.name')
            exitcode        = attributes.get('exitCode')
            # skip not abcdeskop container notification 
            if access_userid is None or  access_type is None or name is None :
                return
            # if exit code is zero
            # skip user notification 
            if int(exitcode) == 0:
                return

            message = "application {} die exit code {}".format(  name, exitcode )
            data = { 'status':  event.get('status'), 
                     'message': message, 
                     'icon':    attributes.get('oc.icon'), 
                     'image':   attributes.get('image'), 
                     'launch':  attributes.get('oc.launch'), 
                     'name':    name }

            oc.od.composer.notify_user( access_userid=access_userid,
                                        access_type=access_type, 
                                        method='container', 
                                        data=data )

        except Exception as e:
            self.logger.error(str(e))


    def loop_forevent(self):    

        # connect to local docker daemon
        client = oc.od.infra.ODInfra().getdockerClient()

        # read events
        self.events = client.events(decode=True) # return docker.types.daemon.CancellableStream
        for event in self.events:
            # self.logger.debug('event from docker event %s', event)
            try:
                if event.get('Type') == 'container':
                    if event.get('Action') == 'oom':
                        self.event_oom(client, event)
                    if event.get('Action') == 'die':
                        self.event_die(client, event)
                if event.get('Type') == 'image':    
                    self.event_image(client, event)
                if event.get('Type') == 'network':  
                    self.event_network(client, event)
            except Exception as e:
                self.logger.error( '%s', e)
        
    def start(self):
        self.logger.debug('starting watcher thread')
        self.thead_event = threading.Thread(target=self.loop_forevent)
        self.thead_event.start() # infinite loop until events.close()

    def stop(self):
        self.logger.debug('stoping watcher thread')
        self.events.close() # this will stop the thread self.thead_event
        self.thead_event.join() 
