"""
Safe command runner helper module.
Provides a secure wrapper around subprocess with timeouts and validation.
"""

import subprocess
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class CommandResult:
    """Result of a command execution."""
    success: bool
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool


class SafeCommandRunner:
    """
    A safe command runner that enforces security guardrails.
    
    Key features:
    - Never uses shell=True
    - Always uses argument lists
    - Enforces timeouts
    - Logs all commands
    - Validates commands against allowlist
    """
    
    def __init__(self, timeout: int = 30, logger: Optional[logging.Logger] = None):
        """
        Initialize the safe command runner.
        
        Args:
            timeout: Default timeout in seconds for all commands
            logger: Logger instance for logging command execution
        """
        self.timeout = timeout
        self.logger = logger or logging.getLogger(__name__)
        
        # Allowlist of safe commands
        self.command_allowlist = {
            'uname',
            'lsb_release',
            'dig',
            'whois',
            'nmap',
            'curl',
            'openssl',
            'gobuster',
        }
    
    def run(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        allow_sudo: bool = False,
    ) -> CommandResult:
        """
        Run a command safely.
        
        Args:
            command: Command as a list of arguments (never a string)
            timeout: Override default timeout (seconds)
            allow_sudo: Whether to allow sudo (default: False)
            
        Returns:
            CommandResult with execution details
            
        Raises:
            ValueError: If command is invalid or unsafe
        """
        # Validate command is a list
        if not isinstance(command, list):
            raise ValueError("Command must be a list of arguments")
        
        # Check for empty command
        if not command:
            raise ValueError("Command cannot be empty")
        
        # Check for sudo
        if not allow_sudo and 'sudo' in command:
            raise ValueError("sudo is not allowed")
        
        # Check command against allowlist
        base_command = command[0]
        if base_command not in self.command_allowlist:
            raise ValueError(f"Command '{base_command}' is not in the allowlist")
        
        # Use provided timeout or default
        actual_timeout = timeout if timeout is not None else self.timeout
        
        # Log the command
        self.logger.info(f"Executing command: {' '.join(command)}")
        
        try:
            # Run the command with subprocess
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=actual_timeout,
                shell=False,  # NEVER use shell=True
            )
            
            # Log the result
            self.logger.info(
                f"Command completed: returncode={result.returncode}, "
                f"stdout_len={len(result.stdout)}, stderr_len={len(result.stderr)}"
            )
            
            return CommandResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                timed_out=False,
            )
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out after {actual_timeout} seconds")
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {actual_timeout} seconds",
                returncode=-1,
                timed_out=True,
            )
        except FileNotFoundError:
            self.logger.error(f"Command not found: {base_command}")
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Command not found: {base_command}. Please ensure it is installed.",
                returncode=-1,
                timed_out=False,
            )
        except Exception as e:
            self.logger.error(f"Unexpected error running command: {e}")
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Unexpected error: {str(e)}",
                returncode=-1,
                timed_out=False,
            )
    
    def add_to_allowlist(self, command: str) -> None:
        """
        Add a command to the allowlist.
        
        Args:
            command: Command name to add (without arguments)
        """
        self.command_allowlist.add(command)
        self.logger.info(f"Added '{command}' to allowlist")
