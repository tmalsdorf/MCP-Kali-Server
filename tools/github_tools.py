"""
GitHub API tools.
Provides passive public repository metadata search functionality.
"""

import logging
import json
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_github_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register GitHub API tools for passive repository metadata search.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    timeout = config.get('tools', {}).get('github', {}).get('scan_timeout', 30)
    
    @mcp.tool()
    def github_metadata_search(query: str, api_key: str = "") -> dict[str, Any]:
        """
        Perform passive public repository metadata search using GitHub API.
        
        This tool searches GitHub for public repositories matching a query,
        returning metadata such as stars, forks, language, and description.
        
        Args:
            query: Search query (e.g., "language:python security", "org:example")
            api_key: GitHub API token (optional, can be set in config.yaml)
        
        Returns:
            Repository metadata including stars, forks, language, description
            
        Raises:
            ValueError: If query is invalid
        """
        logger.info(f"Tool called: github_metadata_search(query={query})")
        
        # Sanitize inputs
        query = validator.sanitize_string(query, max_length=256)
        api_key = validator.sanitize_string(api_key, max_length=100)
        
        # Get API key from config if not provided
        if not api_key:
            api_key = config.get('tools', {}).get('github', {}).get('api_key', '')
        
        # Validate query
        if not query or len(query) < 2:
            error_msg = "Query must be at least 2 characters long"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "query": query
            }
        
        # Build curl command
        if api_key:
            cmd = ["curl", "-s", "-H", f"Authorization: token {api_key}", 
                   f"https://api.github.com/search/repositories?q={query}&per_page=10"]
        else:
            cmd = ["curl", "-s", f"https://api.github.com/search/repositories?q={query}&per_page=10"]
        
        # Execute command
        result = command_runner.run(cmd, timeout=timeout)
        
        if result.success:
            logger.info(f"GitHub search successful for query: {query}")
            try:
                data = json.loads(result.stdout)
                
                # Extract repository information
                repos = []
                for item in data.get('items', []):
                    repo_info = {
                        "name": item.get('name'),
                        "full_name": item.get('full_name'),
                        "description": item.get('description'),
                        "language": item.get('language'),
                        "stars": item.get('stargazers_count'),
                        "forks": item.get('forks_count'),
                        "open_issues": item.get('open_issues_count'),
                        "url": item.get('html_url'),
                        "created_at": item.get('created_at'),
                        "updated_at": item.get('updated_at')
                    }
                    repos.append(repo_info)
                
                return {
                    "success": True,
                    "query": query,
                    "total_count": data.get('total_count', 0),
                    "repositories": repos,
                    "repo_count": len(repos),
                    "raw_output": result.stdout
                }
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse GitHub API response: {e}"
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "query": query,
                    "raw_output": result.stdout
                }
        else:
            error_msg = f"GitHub search failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "query": query
            }
