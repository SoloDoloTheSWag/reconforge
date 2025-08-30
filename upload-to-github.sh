#!/bin/bash

# ReconForge Terminal - GitHub Upload Script
# This script helps upload ReconForge to a new GitHub repository

echo "🚀 ReconForge Terminal - GitHub Upload Helper"
echo "=============================================="
echo ""

# Check if we're in the right directory
if [ ! -f "main.py" ] || [ ! -f "README.md" ]; then
    echo "❌ Error: Please run this script from the ReconForge directory"
    exit 1
fi

# Get GitHub username
echo "📝 GitHub Setup"
read -p "Enter your GitHub username: " GITHUB_USERNAME

if [ -z "$GITHUB_USERNAME" ]; then
    echo "❌ Error: GitHub username is required"
    exit 1
fi

echo ""
echo "📋 Repository Information:"
echo "   Name: reconforge-terminal"
echo "   Username: $GITHUB_USERNAME"
echo "   URL: https://github.com/$GITHUB_USERNAME/reconforge-terminal"
echo ""

# Check if git is configured
GIT_USER=$(git config user.name 2>/dev/null)
GIT_EMAIL=$(git config user.email 2>/dev/null)

if [ -z "$GIT_USER" ] || [ -z "$GIT_EMAIL" ]; then
    echo "⚙️  Git Configuration Required"
    
    if [ -z "$GIT_USER" ]; then
        read -p "Enter your full name for Git: " USER_NAME
        git config --global user.name "$USER_NAME"
    fi
    
    if [ -z "$GIT_EMAIL" ]; then
        read -p "Enter your email for Git: " USER_EMAIL
        git config --global user.email "$USER_EMAIL"
    fi
    echo "✅ Git configured successfully"
    echo ""
fi

# Verify current status
echo "📊 Repository Status:"
echo "   Branch: $(git branch --show-current)"
echo "   Commits: $(git rev-list --count HEAD)"
echo "   Files: $(git ls-files | wc -l)"
echo "   Status: $(git status --porcelain | wc -l) uncommitted changes"
echo ""

# Instructions for GitHub repository creation
echo "🌐 STEP 1: Create GitHub Repository"
echo "=================================="
echo "1. Go to: https://github.com/new"
echo "2. Repository name: reconforge-terminal"
echo "3. Description: Terminal-First Professional Reconnaissance Platform"
echo "4. Set to Public (recommended)"
echo "5. DO NOT initialize with README, .gitignore, or license"
echo "6. Click 'Create repository'"
echo ""

read -p "Have you created the GitHub repository? (y/n): " REPO_CREATED

if [ "$REPO_CREATED" != "y" ] && [ "$REPO_CREATED" != "Y" ]; then
    echo "⏸️  Please create the repository first, then run this script again."
    exit 0
fi

# Set up remote
echo ""
echo "🔗 STEP 2: Connecting to GitHub"
echo "==============================="

REPO_URL="https://github.com/$GITHUB_USERNAME/reconforge-terminal.git"

# Remove existing remote if it exists
git remote remove origin 2>/dev/null

# Add new remote
echo "Adding remote: $REPO_URL"
git remote add origin "$REPO_URL"

# Verify remote
if git remote -v | grep -q "origin"; then
    echo "✅ Remote added successfully"
else
    echo "❌ Failed to add remote"
    exit 1
fi

# Push to GitHub
echo ""
echo "📤 STEP 3: Uploading to GitHub"
echo "=============================="

echo "Renaming branch to 'main'..."
git branch -M main

echo "Pushing to GitHub..."
echo "Note: You may be prompted for your GitHub credentials"
echo ""

if git push -u origin main; then
    echo ""
    echo "🎉 SUCCESS! Repository uploaded successfully!"
    echo "============================================="
    echo ""
    echo "📋 Repository Details:"
    echo "   URL: https://github.com/$GITHUB_USERNAME/reconforge-terminal"
    echo "   Branch: main"
    echo "   Files: $(git ls-files | wc -l) files uploaded"
    echo ""
    echo "🔗 Quick Links:"
    echo "   Repository: https://github.com/$GITHUB_USERNAME/reconforge-terminal"
    echo "   Clone URL: git clone https://github.com/$GITHUB_USERNAME/reconforge-terminal.git"
    echo ""
    echo "✅ Next Steps:"
    echo "   1. Visit your repository to verify all files are present"
    echo "   2. Check that README.md displays correctly"
    echo "   3. Consider creating a release (v2.0.1)"
    echo "   4. Add repository topics/tags for discoverability"
    echo ""
else
    echo ""
    echo "❌ Upload failed. Common solutions:"
    echo ""
    echo "🔐 Authentication Issues:"
    echo "   - Use Personal Access Token instead of password"
    echo "   - Generate at: https://github.com/settings/tokens"
    echo "   - Use token as password when prompted"
    echo ""
    echo "📝 Repository Issues:"
    echo "   - Ensure repository exists and is empty"
    echo "   - Check repository name: reconforge-terminal"
    echo "   - Verify you have write access"
    echo ""
    echo "🔄 Try again with:"
    echo "   git push -u origin main"
fi