#!/usr/bin/env python3
"""
JWT Client Runner

This script provides a simple way to run the JWT client.
"""

import sys
from jwt_client.cli import main as run_cli

def main():
    """Main entry point."""
    return run_cli()

if __name__ == "__main__":
    sys.exit(main())
