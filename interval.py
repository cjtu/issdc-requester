import threading
import time

class SetInterval:
  def __init__(self, function, interval) :
    self.function = function
    self.interval = interval
    self.stop_event = threading.Event()
    thread = threading.Thread(target=self.__setInterval)
    thread.daemon = True # Will die when the main thread dies
    thread.start()

  def __setInterval(self) :
    next = time.time() + self.interval
    while not self.stop_event.wait(next - time.time()) :
      next += self.interval
      self.function()

  def stop(self) :
    self.stop_event.set()
