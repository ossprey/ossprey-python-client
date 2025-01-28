#!/bin/bash 
# Setup poetry
pip install poetry==2.0.1
poetry install

# Git Config
git config --global push.default current

# Copy pre-push
cp .githooks/pre-push .git/hooks/pre-push

echo "Startup complete"
