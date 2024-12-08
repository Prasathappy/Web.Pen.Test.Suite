import threading

class ConcurrentExecutor:
    def __init__(self, func, targets, threads=5):
        self.func = func
        self.targets = targets
        self.threads = threads

    def execute(self):
        threads = []
        for target in self.targets:
            thread = threading.Thread(target=self.func, args=(target,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
