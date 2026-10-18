"""
Logging utilities for TRACEWISE-Lite
"""

import logging
import sys
from datetime import datetime
from pathlib import Path


def setup_logger(name: str = "tracewise", level: str = "INFO", log_file: str = None):
    """
    Setup a logger with consistent formatting

    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional log file path

    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler with colored output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)

    # Format
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


class ProgressTracker:
    """Track progress of long-running operations"""

    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = datetime.now()

    def update(self, increment: int = 1):
        """Update progress"""
        self.current += increment
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\r{self.description}: {self.current}/{self.total} ({percentage:.1f}%) - {elapsed:.1f}s",
              end='', flush=True)

    def finish(self):
        """Mark as complete"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{self.description} completed in {elapsed:.1f}s")