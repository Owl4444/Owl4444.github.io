#!/bin/bash

# Check if commit message is provided
if [ "$#" -ne 1 ]; then
    echo "Error: You must provide a commit message."
    exit 1
fi

# Commit message
COMMIT_MSG="$1"

# Build the Jekyll site
echo "Building the Jekyll site..."
bundle exec jekyll build

if [ $? -ne 0 ]; then
    echo "Error: Jekyll build failed."
    exit 1
fi

# Add all changes to git
echo "Staging changes in Source..."
git add -A

# Commit with provided message
echo "Committing with message: $COMMIT_MSG"
git commit -m "$COMMIT_MSG"

# Push to repository
echo "Pushing to repository..."
git push

echo "Cloning site to Owl4444.github.io"
cp -r _site/* /root/Owl4444.github.io


cd /root/Owl4444.github.io

# Add all changes to git
echo "Staging changes in gitpage ..."
git add -A

# Commit with provided message
echo "Committing with message: $COMMIT_MSG"
git commit -m "$COMMIT_MSG"

# Push to repository
echo "Pushing to repository..."
git push


echo "DONEE!!"


