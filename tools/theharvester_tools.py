"""
theHarvester tools.
Provides passive email/domain discovery functionality.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_theharvester_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register theHarvester tools for passive reconnaissance.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    timeout = config.get('tools', {}).get('theharvester', {}).get('scan_timeout', 120)
    
    @mcp.tool()
    def theharvester_passive(domain: str, sources: str = "all") -> dict[str, Any]:
        """
        Perform passive email and domain discovery using theHarvester.
        
        This tool uses ONLY passive sources (no active DNS queries):
        - bing, bingapi, google, googleCSE, google-profiles
        - pgp, virustotal, threatcrowd, crtsh, securitytrails
        - shodan, hunter, censys, spyse, mcafee
        
        Args:
            domain: The target domain (e.g., example.com)
            sources: Data sources to use (default: "all")
                    Options: bing, google, pgp, virustotal, crtsh, etc.
                    Use "all" for comprehensive passive search
        
        Returns:
            Discovered emails, subdomains, and hosts
            
        Raises:
            ValueError: If domain is invalid
        """
        logger.info(f"Tool called: theharvester_passive(domain={domain}, sources={sources})")
        
        # Sanitize inputs
        domain = validator.sanitize_string(domain, max_length=253)
        sources = validator.sanitize_string(sources, max_length=100)
        
        # Validate domain
        if not validator.validate_domain(domain):
            error_msg = f"Invalid domain: {domain}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
        
        # Validate sources (allow only passive sources)
        passive_sources = [
            "bing", "bingapi", "google", "googleCSE", "google-profiles",
            "pgp", "virustotal", "threatcrowd", "crtsh", "securitytrails",
            "shodan", "hunter", "censys", "spyse", "mcafee", "all"
        ]
        
        if sources != "all":
            source_list = [s.strip().lower() for s in sources.split(',')]
            for source in source_list:
                if source not in passive_sources:
                    error_msg = f"Invalid or non-passive source: {source}. Allowed: {', '.join(passive_sources)}"
                    logger.warning(error_msg)
                    return {
                        "success": False,
                        "error": error_msg,
                        "domain": domain
                    }
        
        # Build theHarvester command with passive-only flags
        cmd = ["theHarvester", "-d", domain, "-b", sources, "-l", "100"]
        
        # Execute command
        result = command_runner.run(cmd, timeout=timeout)
        
        if result.success:
            logger.info(f"theHarvester passive scan successful for {domain}")
            # Parse output to extract emails, hosts, and subdomains
            emails = []
            hosts = []
            subdomains = []
            
            lines = result.stdout.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('[*] Emails found:'):
                    current_section = 'emails'
                elif line.startswith('[*] Hosts found:'):
                    current_section = 'hosts'
                elif line.startswith('[*] Subdomains found:'):
                    current_section = 'subdomains'
                elif line and not line.startswith('[*]') and not line.startswith('-'):
                    if current_section == 'emails' and '@' in line:
                        emails.append(line)
                    elif current_section == 'hosts':
                        hosts.append(line)
                    elif current_section == 'subdomains':
                        subdomains.append(line)
            
            return {
                "success": True,
                "domain": domain,
                "sources": sources,
                "emails": emails,
                "hosts": hosts,
                "subdomains": subdomains,
                "email_count": len(emails),
                "host_count": len(hosts),
                "subdomain_count": len(subdomains),
                "raw_output": result.stdout
            }
        else:
            error_msg = f"theHarvester scan failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
