import logging 
import threading
import oc.logging

from kubernetes import client, watch


logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODKubernetesWatcher:

    def __init__(self):
        self.orchestrator = oc.od.orchestrator.ODOrchestratorKubernetes()
        self.thead_event = None


    def loopforevent( self ):
        self.logger.debug('' )
        # watch list_namespaced_pod waiting for a valid ip addr
        w = watch.Watch()                 
        for event in w.stream(  self.orchestrator.kubeapi.list_namespaced_pod, namespace=self.orchestrator.namespace):   
            # event must be a dict, else continue
            if not isinstance(event,dict):
                self.logger.error( 'event type is %s, and should be a dict, skipping event', type( event ))
                continue

            # event dict must contain a type 
            event_type = event.get('type')
            if event_type == 'MODIFIED':
                self.logger.debug( f"event {event_type} receive" )
                # event dict must contain a object 
                pod_event = event.get('object')
                # if podevent type is pod
                if isinstance( pod_event, client.models.v1_pod.V1Pod ) : 
                    self.logger.debug( f"{event_type} -> {pod_event.metadata.name}" )
                    podtype = pod_event.metadata.labels.get( 'type' )
                    if podtype == self.orchestrator.applicationtype :
                        self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
                        if isinstance( pod_event.status, client.models.v1_pod_status.V1PodStatus ):
                            if not isinstance(pod_event.status.container_statuses, list):
                                continue
                            state = pod_event.status.container_statuses[0].state     
                            if isinstance( state.terminated, client.models.v1_container_state_terminated.V1ContainerStateTerminated ):
                                self.logger.debug( f"{event_type} -> {pod_event.metadata.name} phase: {pod_event.status.phase} reason:{state.terminated.reason}" )
                                if state.terminated.reason == 'Completed':
                                    self.orchestrator.removePod( pod_event )

            if event_type == 'DELETED':
                self.logger.debug( f"event {event_type} receive" )
                # event dict must contain a object 
                pod_event = event.get('object')
                # if podevent type is pod
                if isinstance( pod_event, client.models.v1_pod.V1Pod ) : 
                    self.logger.debug( f"{event_type} -> {pod_event.metadata.name}" )
                    podtype = pod_event.metadata.labels.get( 'type' )
                    if podtype == self.orchestrator.x11servertype :
                        self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
                        desktop = self.orchestrator.pod2desktop( pod_event )
                        oc.od.composer.detach_container_from_network(desktop.name)
                    
        
    def start(self):
        self.logger.debug('starting watcher thread')
        self.thead_event = threading.Thread(target=self.loopforevent)
        self.thead_event.start() # infinite loop until events.close()

    def stop(self):
        self.logger.debug('stoping watcher thread')
        if isinstance( self.thead_event, threading.Thread ):
            if self.thead_event.is_alive() :
                self.events.close() # this will stop the thread self.thead_event
                self.thead_event.join()
            else:
                self.logger.debug('thread watcher is not alive')
            
