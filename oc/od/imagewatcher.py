import logging 
import threading
import oc.logging

logger = logging.getLogger(__name__)

class ODImageWatcher:

    def __init__(self):
        pass

    def event_image( self, client, event ):
        pass
     
    def start(self):
        logger.debug('starting image watcher thread')
        # self.thead_event = threading.Thread(target=self.loop_forevent)
        # self.thead_event.start() # infinite loop until events.close()

    def stop(self):
        logger.debug('stoping image watcher thread')
        # self.events.close() # this will stop the thread self.thead_event
        # self.thead_event.join() 
