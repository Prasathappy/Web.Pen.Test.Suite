import logging

class Logger:
    def __init__(self, log_file="pentest.log"):
        self.logger = logging.getLogger("PenTestSuite")
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            file_handler = logging.FileHandler(log_file)
            console_handler = logging.StreamHandler()

            file_formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S"
            )
            console_formatter = logging.Formatter("%(levelname)s: %(message)s")

            file_handler.setFormatter(file_formatter)
            console_handler.setFormatter(console_formatter)

            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def log(self, message, level="info"):
        if level == "debug":
            self.logger.debug(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "error":
            self.logger.error(message)
        else:
            self.logger.info(message)
