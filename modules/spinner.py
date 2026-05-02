import sys
import time
import itertools
import threading

class Spinner:
    def __init__(self, message="Scanning..."):
        self.spinner = itertools.cycle(['-', '/', '|', '\\'])
        self.delay = 0.1
        self.busy = False
        self.spinner_visible = False
        self.message = message
        self.thread = None

    def write_next(self):
        with self._screen_lock:
            if not self.spinner_visible:
                sys.stdout.write(f"\r    [~] {self.message} {next(self.spinner)}")
                self.spinner_visible = True
                sys.stdout.flush()

    def remove_spinner(self, cleanup=False):
        with self._screen_lock:
            if self.spinner_visible:
                sys.stdout.write('\b' * (len(self.message) + 10)) # Erase line
                self.spinner_visible = False
                if cleanup:
                    sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
                sys.stdout.flush()

    def spinner_task(self):
        while self.busy:
            self.write_next()
            time.sleep(self.delay)
            self.remove_spinner()

    def start(self):
        self.busy = True
        self._screen_lock = threading.Lock()
        self.thread = threading.Thread(target=self.spinner_task)
        self.thread.start()

    def stop(self, success_message=None):
        self.busy = False
        time.sleep(self.delay)
        if self.thread:
            self.thread.join()
        self.remove_spinner(cleanup=True)
        if success_message:
            print(f"    [+] {success_message}")
