"""
System information tools.
Provides safe access to basic system information.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner


def register_system_tools(mcp: FastMCP, command_runner: SafeCommandRunner, logger: logging.Logger) -> None:
    """
    Register system information tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
    """
    
    @mcp.tool()
    def get_system_info() -> dict[str, Any]:
        """
        Get basic system information.
        
        Returns system information including:
        - Kernel version (uname -a)
        - OS distribution info (lsb_release -a)
        
        This is a read-only operation and safe to run.
        """
        logger.info("Tool called: get_system_info")
        
        results = {
            "kernel_info": "",
            "distribution_info": "",
            "error": None
        }
        
        # Get kernel info
        uname_result = command_runner.run(["uname", "-a"])
        if uname_result.success:
            results["kernel_info"] = uname_result.stdout.strip()
        else:
            results["error"] = f"uname failed: {uname_result.stderr}"
            logger.warning(f"uname command failed: {uname_result.stderr}")
        
        # Get distribution info
        lsb_result = command_runner.run(["lsb_release", "-a"])
        if lsb_result.success:
            results["distribution_info"] = lsb_result.stdout.strip()
        else:
            # lsb_release might not be available on all systems
            if not results["error"]:
                results["error"] = f"lsb_release failed: {lsb_result.stderr}"
            logger.warning(f"lsb_release command failed: {lsb_result.stderr}")
        
        logger.info("get_system_info completed successfully")
        return results
    
    @mcp.tool()
    def list_kali_tools() -> dict[str, Any]:
        """
        List available Kali Linux security tools.
        
        Returns a list of installed security tools by checking:
        - Installed kali-tools packages
        - Common security tool binaries
        
        This is a read-only operation and safe to run.
        """
        logger.info("Tool called: list_kali_tools")
        
        results = {
            "kali_tool_packages": [],
            "security_binaries": [],
            "error": None
        }
        
        # Get installed kali-tools packages
        dpkg_result = command_runner.run(["dpkg", "-l", "kali-tools-*"], timeout=60)
        if dpkg_result.success:
            results["kali_tool_packages"] = dpkg_result.stdout.strip()
        else:
            results["error"] = f"dpkg command failed: {dpkg_result.stderr}"
            logger.warning(f"dpkg command failed: {dpkg_result.stderr}")
        
        # List common security tool binaries from /usr/bin
        # This is a safe read-only operation
        ls_result = command_runner.run(["ls", "/usr/bin"], timeout=30)
        if ls_result.success:
            # Filter for common security tool names
            security_keywords = ['nmap', 'wireshark', 'metasploit', 'burpsuite', 'sqlmap', 
                                'hydra', 'john', 'hashcat', 'aircrack', 'gobuster', 'nikto',
                                'netcat', 'tcpdump', 'wireshark', 'ettercap', 'maltego']
            
            binaries = ls_result.stdout.strip().split('\n')
            security_binaries = [b for b in binaries if any(keyword in b.lower() for keyword in security_keywords)]
            results["security_binaries"] = security_binaries
        else:
            if not results["error"]:
                results["error"] = f"ls command failed: {ls_result.stderr}"
            logger.warning(f"ls command failed: {ls_result.stderr}")
        
        logger.info("list_kali_tools completed successfully")
        return results
