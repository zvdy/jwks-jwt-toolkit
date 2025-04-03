#!/usr/bin/env python3
"""
JWKS Server Runner

This script provides a simple way to start the JWKS server.
"""

import os
import argparse
import logging
from jwks_server.app import main as run_server
from jwks_server.config import config_map

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run the JWKS server')
    parser.add_argument(
        '--env', 
        choices=config_map.keys(), 
        default='development',
        help='Environment to use (default: development)'
    )
    parser.add_argument(
        '--host',
        default=None,
        help='Host to bind to (overrides config)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=None,
        help='Port to bind to (overrides config)'
    )
    return parser.parse_args()

def main():
    """Main entry point."""
    args = parse_args()
    
    # Set environment
    os.environ['JWKS_ENV'] = args.env
    
    # Override host/port if provided
    if args.host:
        os.environ['JWKS_HOST'] = args.host
    if args.port:
        os.environ['JWKS_PORT'] = str(args.port)
    
    logger.info(f"Starting JWKS server in {args.env} environment")
    run_server()

if __name__ == "__main__":
    main()
