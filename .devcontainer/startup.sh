#!/bin/bash
# Setup poetry
poetry config virtualenvs.in-project true
poetry install

# Git Config
git config --global push.default current

# Copy pre-push
cp .githooks/pre-push .git/hooks/pre-push

echo "Startup complete"
