#!/usr/bin/env bash
set -e

# Colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running CI pipeline locally...${NC}"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
  echo -e "${YELLOW}Creating virtual environment...${NC}"
  python -m venv .venv
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source .venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install --upgrade pip
pip install pytest pytest-cov
pip install -e .

# Run tests
echo -e "${YELLOW}Running tests with pytest...${NC}"
pytest tests/ --cov=jwks_server --cov=jwt_client --cov-report=term --cov-report=xml

# Check if tests passed
if [ $? -eq 0 ]; then
  echo -e "${GREEN}All tests passed!${NC}"
else
  echo -e "${RED}Tests failed!${NC}"
  exit 1
fi

# Deactivate virtual environment
deactivate

echo -e "${GREEN}CI pipeline completed successfully!${NC}"
