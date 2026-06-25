import logging 
import threading
import asyncio
import urllib3.exceptions
import oc.logging
import time

from kubernetes_asyncio import client, watch
from kubernetes_asyncio.client.rest import ApiException
from kubernetes_asyncio.client.models.v1_pod import V1Pod
from kubernetes_asyncio.client.models.v1_pod_status import V1PodStatus
from kubernetes_asyncio.client.models.v1_container_state_terminated import V1ContainerStateTerminated
from kubernetes_asyncio.client.models.core_v1_event import CoreV1Event

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODKubernetesWatcher:

    def __init__(self):
        self.orchestrator = oc.od.orchestrator.ODOrchestratorKubernetes()
        self.thead_event = None
        self.watch = None
        self.DEFAULT_K8S_WATCHER_TIMEOUT_SECONDS = 10
        self._backoff_min = 5   # seconds
        self._backoff_max = 60  # seconds
        self.logger.debug( f"ODKubernetesWatcher use namespace={self.orchestrator.namespace}")

    async def loopforevent( self ):
        # self.logger.debug('' )
        self.watch = watch.Watch()
        _backoff = self._backoff_min
        # self.logger.debug('loopforevent start inifity loop')
        while( True ):
            try:
                async for event in self.watch.stream( self.orchestrator.kubeapi.list_namespaced_pod, namespace=self.orchestrator.namespace ):
                    if self.watch._stop :
                        self.watch.stop()
                        self.watch.close()
                        return  # stop this thread 

                    # event must be a dict, else continue
                    if not isinstance(event,dict):
                        self.logger.error( f"event type is {type(event)}, and should be a dict, skipping event")
                        continue
                    _backoff = self._backoff_min  # reset backoff on successful event
                    
                    # event dict must contain a object 
                    pod_event = event.get('object')
                    # event dict must contain a type 
                    event_type = event.get('type')
                    # self.logger.debug( f"event_type={event_type} pod_event={type(pod_event)}" )

                    if event_type == 'MODIFIED':
                        # if podevent type is pod
                        # self.logger.debug( f"event_type={event_type} pod_event={type(pod_event)}" )
                        if isinstance( pod_event, V1Pod ) and isinstance(pod_event.metadata.labels, dict) :
                            podtype = pod_event.metadata.labels.get('type')
                            # if podtype == self.orchestrator.pod_application :
                            #    self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
                            if podtype in [ self.orchestrator.pod_application_pull, self.orchestrator.pod_application ]:
                                # self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
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
                                                await self.orchestrator.removePod( pod_event )
                                        if state.terminated.reason == 'OOMKilled':
                                            self.logger.debug( f"pod={pod_event.metadata.name} reason={state.terminated.reason} phase={pod_event.status.phase}" )
                                            if pod_event.status.phase == 'Running':
                                                self.logger.debug( f"RemovePod pod={pod_event.metadata.name} reason={state.terminated.reason}" )
                                                deletedPod = await self.orchestrator.removePod( pod_event )
                                                if isinstance( deletedPod, V1Pod ):
                                                    self.logger.debug( f"watcher send notify_user_from_pod_application pod={pod_event.metadata.name} reason={state.terminated.reason}" )
                                                    await oc.od.composer.notify_user_from_pod_application( pod_application=pod_event, message=state.terminated.reason )

                    elif event_type == 'DELETED':
                        # if podevent type is pod
                        # self.logger.debug( f"event_type={event_type} pod_event={type(pod_event)}" )
                        if isinstance( pod_event, V1Pod ) and isinstance(pod_event.metadata.labels, dict) :
                            # self.logger.debug( f"{event_type} -> {pod_event.metadata.name}" )
                            podtype = pod_event.metadata.labels.get( 'type' )
                            if podtype == self.orchestrator.x11servertype :
                                self.logger.debug( f"{event_type} -> {pod_event.metadata.name}:{podtype}" )
                                desktop = self.orchestrator.pod2desktop_reduced( pod_event )
                                await oc.od.composer.detach_container_from_network(desktop.name)
            
            except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.MaxRetryError) as e:
                self.logger.fatal( e )
                self.logger.fatal( f"ODKubernetesWatcher will not die but the api server is not responding {type(e)}, sleeping for {_backoff} s" )
                await asyncio.sleep(_backoff)
                _backoff = min( _backoff * 2, self._backoff_max ) 
            
            except client.exceptions.ApiException as e:
                self.logger.error( f"{type(e)} {e}" )
                if hasattr(e,'status') and e.status == 401 :
                    self.logger.fatal( f"exit loopforevent threading, this error is fatal" )
                    return
                
                if hasattr(e, 'status') and e.status == 504 and \
                    hasattr(e, 'reason') and 'Too large resource version' in e.reason :
                    self.logger.debug( f"retrying after Timeout: Too large resource version ApiException {e}")
                    

                self.logger.error( f"{type(e)} {e}" )
                await asyncio.sleep(_backoff) # exponential backoff to prevent log avalanche
                _backoff = min( _backoff * 2, self._backoff_max )

            except Exception as e:
                pass
                # self.logger.error( f"{type(e)} {e}" )
                # await asyncio.sleep(_backoff)
                # _backoff = min( _backoff * 2, self._backoff_max )

        
                    
    def start(self):
        # self.thead_event = threading.Thread(target=self.loopforevent)
        # self.thead_event.start() # infinite loop until events.close()
        self.background_task_loopforevent = asyncio.create_task( self.loopforevent() )



    def stop(self):
        self.logger.debug('watcher thread is stopping')
        while isinstance( self.thead_event, threading.Thread ) and hasattr(self.thead_event, 'is_alive') :
            if self.thead_event.is_alive() :
                self.logger.debug('thread watcher is alive')
                if isinstance(self.watch, watch.Watch ) :
                    # self.logger.debug('ODKubernetesWatcher watch closing')
                    self.watch.stop() # this will stop the thread self.thead_event
                    # self.logger.debug('ODKubernetesWatcher watch closed')
                # self.logger.debug('ODKubernetesWatcher join start timeout=5')
                self.thead_event.join(timeout=5)
                # self.logger.debug('ODKubernetesWatcher join done')
            else:
                self.logger.debug('thread watcher is not alive')
                break

        self.watch = None
        self.thead_event = None

        self.logger.debug('ODKubernetesWatcher thread stopped')
            
