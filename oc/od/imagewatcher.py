import logging 
import threading
import oc.logging

logger = logging.getLogger(__name__)

class ODImageWatcher:

    def __init__(self, ODApps):
        pass

    def loopforevent( self ):
        stream = db.collection.watch()
        while stream.alive:
            change = stream.try_next()
            # Note that the ChangeStream's resume token may be updated
            # even when no changes are returned.
            print("Current resume token: %r" % (stream.resume_token,))
            if change is not None:
                print("Change document: %r" % (change,))
                continue
            # We end up here when there are no recent changes.
            # Sleep for a while before trying again to avoid flooding
            # the server with getMore requests when no changes are
            # available.
            time.sleep(10)


    def event_image( self, client, event ):
        pass
     
    def start(self):
        logger.debug('starting image watcher thread')
        self.logger.debug('starting watcher thread')
        self.thead_event = threading.Thread(target=self.loopforevent)
        self.thead_event.start() # infinite loop until events.close()

    def stop(self):
        self.logger.debug('ODImageWatcher thread stopping')
        if isinstance( self.thead_event, threading.Thread ):
            while self.thead_event.is_alive():
                self.logger.debug('thread watcher is alive')
                if isinstance(self.watch, watch.Watch ) :
                    self.logger.debug('ODKubernetesWatcher watch closing')
                    self.watch.stop() # this will stop the thread self.thead_event
                    self.logger.debug('ODKubernetesWatcher watch closed')
              
                self.logger.debug('ODImageWatcher join start timeout=5')
                self.thead_event.join(timeout=5)
                self.logger.debug('ODImageWatcher join done')
            else:
                self.logger.debug('thread watcher is not alive')
