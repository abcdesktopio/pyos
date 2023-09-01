import logging 
import threading
import oc.logging

from kubernetes import client, watch
from kubernetes.client.models.v1_pod import V1Pod
from kubernetes.client.models.v1_pod_status import V1PodStatus
from kubernetes.client.models.v1_container_status import V1ContainerStatus
from kubernetes.client.models.v1_container_state import V1ContainerState
from kubernetes.client.models.v1_container_state_terminated import V1ContainerStateTerminated

from   oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and AuthUser

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODKubernetesWatcher:

    def __init__(self):
        self.orchestrator = oc.od.orchestrator.ODOrchestratorKubernetes()
        self.thead_event = None
        self.watch = None
        self.DEFAULT_K8S_WATCHER_TIMEOUT_SECONDS = 10
        self.logger.debug( f"ODKubernetesWatcher use namespace={self.orchestrator.namespace}")

    def loopforevent( self ):
        self.logger.debug('' )
        self.watch = watch.Watch() 
        self.logger.debug('loopforevent start inifity loop')
        while( True ): #  inifity loop stop when watch.stop     
            try:
                # watch list_namespaced_pod waiting for a valid ip addr          
                events = self.watch.stream(  self.orchestrator.kubeapi.list_namespaced_pod, namespace=self.orchestrator.namespace, timeout_seconds=self.DEFAULT_K8S_WATCHER_TIMEOUT_SECONDS)
                # events = self.watch.stream(  self.orchestrator.kubeapi.list_namespaced_ , namespace=self.orchestrator.namespace, timeout_seconds=self.DEFAULT_K8S_WATCHER_TIMEOUT_SECONDS)
                if self.watch._stop :
                    return  # stop this thread 
                
                for event in events:
                    # event must be a dict, else continue
                    if not isinstance(event,dict):
                        self.logger.error( f"event type is {type(event)}, and should be a dict, skipping event")
                        continue
                    
                    # event dict must contain a object 
                    pod_event = event.get('object')
                    # event dict must contain a type 
                    event_type = event.get('type')

                    if event_type == 'MODIFIED':
                        # if podevent type is pod
                        if isinstance( pod_event, V1Pod ) : 
                            podtype = pod_event.metadata.labels.get('type')
                            # if podtype == self.orchestrator.pod_application :
                            #    self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
                            if podtype == self.orchestrator.pod_application_pull or \
                                podtype == self.orchestrator.pod_application  :
                                self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
                                if isinstance( pod_event.status, V1PodStatus ):
                                    if not isinstance(pod_event.status.container_statuses, list):
                                        continue
                                    state = pod_event.status.container_statuses[0].state
                                    if isinstance( state.terminated, V1ContainerStateTerminated ):
                                        self.logger.debug( f"EVENT={event_type} pod={pod_event.metadata.name} phase={pod_event.status.phase} reason:{state.terminated.reason}" )
                                        if state.terminated.reason == 'Completed':
                                            # the pod is terminated status is 'Completed'
                                            # pod_event.status.phase == 'Succeeded' or
                                            if pod_event.status.phase == 'Running':
                                                self.orchestrator.removePod( pod_event )
                                        if state.terminated.reason == 'OOMKilled':
                                            self.logger.debug( f"pod={pod_event.metadata.name} reason={state.terminated.reason} phase={pod_event.status.phase}" )
                                            if pod_event.status.phase == 'Running':
                                                self.logger.debug( f"RemovePod pod={pod_event.metadata.name} reason={state.terminated.reason}" )
                                                deletedPod = self.orchestrator.removePod( pod_event )
                                                if isinstance( deletedPod, V1Pod ):
                                                    self.logger.debug( f"watcher send notify_user_from_pod_application pod={pod_event.metadata.name} reason={state.terminated.reason}" )
                                                    oc.od.composer.notify_user_from_pod_application( pod_application=pod_event, message=state.terminated.reason )

                    elif event_type == 'DELETED':
                        # if podevent type is pod
                        if isinstance( pod_event, V1Pod ) : 
                            self.logger.debug( f"{event_type} -> {pod_event.metadata.name}" )
                            podtype = pod_event.metadata.labels.get( 'type' )
                            if podtype == self.orchestrator.x11servertype :
                                self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
                                desktop = self.orchestrator.pod2desktop( pod_event )
                                oc.od.composer.detach_container_from_network(desktop.name)

            except Exception as e:
                self.logger.debug( e )
                pass
                    
    def start(self):
        self.logger.debug('starting watcher thread')
        self.thead_event = threading.Thread(target=self.loopforevent)
        self.thead_event.start() # infinite loop until events.close()

    def stop(self):
        self.logger.debug('ODKubernetesWatcher thread stopping')
        if isinstance( self.thead_event, threading.Thread ):
            while self.thead_event.is_alive():
                self.logger.debug('thread watcher is alive')
                if isinstance(self.watch, watch.Watch ) :
                    self.logger.debug('ODKubernetesWatcher watch closing')
                    self.watch.stop() # this will stop the thread self.thead_event
                    self.logger.debug('ODKubernetesWatcher watch closed')
              
                self.logger.debug('ODKubernetesWatcher join start timeout=5')
                self.thead_event.join(timeout=5)
                self.logger.debug('ODKubernetesWatcher join done')
            else:
                self.logger.debug('thread watcher is not alive')

        self.watch = None
        self.thead_event = None

        self.logger.debug('ODKubernetesWatcher thread stopped')
            
