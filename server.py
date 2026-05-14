"""
MCP-Kali-Server: A safe MCP server for Kali Linux security tools.
"""

import sys
import yaml
import logging
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator
from logging_setup import setup_logging


def load_config(config_path: str = "config.yaml") -> dict:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config or {}
    except FileNotFoundError:
        print(f"Warning: Config file {config_path} not found. Using defaults.")
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing config file: {e}")
        return {}


def create_server() -> FastMCP:
    """
    Create and configure the MCP server.
    
    Returns:
        Configured FastMCP server instance
    """
    # Load configuration
    config = load_config()
    
    # Setup logging
    log_level = config.get('server', {}).get('log_level', 'INFO')
    log_file = config.get('server', {}).get('log_file', 'logs/mcp_kali_server.log')
    logger = setup_logging(log_file=log_file, log_level=log_level)
    
    logger.info("Starting MCP-Kali-Server")
    
    # Create MCP server
    server_name = config.get('server', {}).get('name', 'mcp-kali-server')
    mcp = FastMCP(server_name)
    
    # Initialize safe command runner
    command_timeout = config.get('safety', {}).get('command_timeout', 30)
    command_runner = SafeCommandRunner(timeout=command_timeout, logger=logger)
    
    # Register all tools
    logger.info("Registering tools...")
    
    try:
        from tools import (
            register_system_tools,
            register_dns_tools,
            register_nmap_tools,
            register_http_tools,
            register_ssl_tools,
            register_whois_tools,
            register_gobuster_tools,
            register_dirb_tools,
        )
        
        # Register system tools
        register_system_tools(mcp, command_runner, logger)
        logger.info("System tools registered")
        
        # Register DNS tools
        register_dns_tools(mcp, command_runner, logger, config)
        logger.info("DNS tools registered")
        
        # Register whois tools
        register_whois_tools(mcp, command_runner, logger)
        logger.info("Whois tools registered")
        
        # Register nmap tools
        register_nmap_tools(mcp, command_runner, logger, config)
        logger.info("Nmap tools registered")
        
        # Register HTTP tools
        register_http_tools(mcp, command_runner, logger, config)
        logger.info("HTTP tools registered")
        
        # Register SSL tools
        register_ssl_tools(mcp, command_runner, logger, config)
        logger.info("SSL tools registered")
        
        # Register gobuster tools
        register_gobuster_tools(mcp, command_runner, logger, config)
        logger.info("Gobuster tools registered")
        
        # Register dirb tools
        register_dirb_tools(mcp, command_runner, logger, config)
        logger.info("Dirb tools registered")
        
        logger.info("All tools registered successfully")
        
    except ImportError as e:
        logger.error(f"Failed to import tool modules: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to register tools: {e}")
        raise
    
    # Add server info tool
    @mcp.tool()
    def server_info() -> dict:
        """
        Get server information and safety settings.
        
        Returns:
            Server configuration and safety information
        """
        logger.info("Tool called: server_info")
        
        return {
            "server_name": server_name,
            "version": config.get('server', {}).get('version', '0.1.0'),
            "safety": {
                "allow_public_ips": config.get('safety', {}).get('allow_public_ips', False),
                "command_timeout": config.get('safety', {}).get('command_timeout', 30),
                "max_concurrent_operations": config.get('safety', {}).get('max_concurrent_operations', 3),
            },
            "tools": {
                "nmap": {
                    "allowed_scan_types": config.get('tools', {}).get('nmap', {}).get('allowed_scan_types', []),
                },
                "dns": {
                    "allowed_record_types": config.get('tools', {}).get('dns', {}).get('allowed_record_types', []),
                },
                "http": {
                    "allowed_schemes": config.get('tools', {}).get('http', {}).get('allowed_schemes', []),
                },
            }
        }
    
    logger.info("MCP-Kali-Server initialized successfully")
    return mcp


def main():
    """
    Main entry point for the MCP server.
    """
    try:
        mcp = create_server()
        mcp.run()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
