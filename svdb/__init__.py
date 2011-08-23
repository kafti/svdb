import logging

class NullHandler(logging.Handler):
    """NullHandler instances do nothing with error messages.
    Used for avoiding the 'No handlers could be found for logger XXX' message
    which can be displayed if the library user has not configured logging.
    """
    def emit(self, record):
        pass
    
    def handle(self, record):
        pass
    
    def createLock(self):
        pass

h = NullHandler()
logging.getLogger("svdb").addHandler(h)
