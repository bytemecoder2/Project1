import logging

class Logger:
    def __init__(self, name: str, log_filename: str,
                 console_level=logging.WARNING, file_level=logging.DEBUG):
        """
        Initialize the Logger instance.

        Args:
            name (str): Logger name.
            log_filename (str): File path to save logs.
            console_level (int): Logging level for console output.
            file_level (int): Logging level for file output.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Capture all levels globally

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S")

        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)
        console_handler.setFormatter(formatter)

        # Setup file handler
        file_handler = logging.FileHandler(log_filename)
        file_handler.setLevel(file_level)
        file_handler.setFormatter(formatter)

        # Avoid adding handlers multiple times if multiple Logger instances use the same name
        if not self.logger.hasHandlers():
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

    def get_logger(self):
        """Return the underlying logger instance."""
        return self.logger

    def set_console_level(self, level):
        """Set the logging level for the console handler."""
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(level)

    def set_file_level(self, level):
        """Set the logging level for the file handler."""
        for handler in self.logger.handlers:
            if isinstance(handler, logging.FileHandler):
                handler.setLevel(level)
