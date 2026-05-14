"""
Logging setup module.
Configures logging for the MCP server with file rotation.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional


def setup_logging(
    log_file: str = "logs/mcp_kali_server.log",
    log_level: str = "INFO",
    log_to_console: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
) -> logging.Logger:
    """
    Set up logging for the MCP server.
    
    Args:
        log_file: Path to the log file
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_console: Whether to also log to console
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup log files to keep
        
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger("mcp_kali_server")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, log_level.upper()))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (defaults to mcp_kali_server)
        
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f"mcp_kali_server.{name}")
    return logging.getLogger("mcp_kali_server")
