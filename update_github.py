#!/usr/bin/env python3
"""
update_github.py
Updates the GitHub Repository description (About) and topics (Tags/Topics)
by parsing the "## GitHub Repository Settings" section in README.md.

Requirements:
- Python 3.x
- Git command-line tool (to detect repository information)
- A GitHub Personal Access Token (PAT) with repository settings write access.
  Can be provided via:
  1. --token command-line argument
  2. GITHUB_TOKEN environment variable
  3. GH_TOKEN environment variable
"""

import os
import re
import sys
import json
import urllib.request
import urllib.error
import subprocess

def get_git_repo_info():
    """Extract owner and repo name from git remote origin URL."""
    try:
        url = subprocess.check_output(["git", "config", "--get", "remote.origin.url"], text=True).strip()
        # Handle SSH URL: git@github.com:owner/repo.git
        # Handle HTTPS URL: https://github.com/owner/repo.git or https://github.com/owner/repo
        match = re.search(r"github\.com[:/]([^/]+)/([^/.]+)(?:\.git)?", url)
        if match:
            return match.group(1), match.group(2)
    except Exception as e:
        print(f"Warning: Could not determine git repo info via command: {e}")
    
    # Fallback/Default if git fails or is not a github repository
    return "arumes31", "blocklist"

def parse_readme():
    """Parse README.md to extract About and Topics."""
    about = None
    topics = []
    
    readme_path = "README.md"
    if not os.path.exists(readme_path):
        print(f"Error: {readme_path} not found.")
        return about, topics

    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Find the GitHub Repository Settings section
    section_match = re.search(r"## GitHub Repository Settings(.*?)(?:##|$)", content, re.DOTALL | re.IGNORECASE)
    if not section_match:
        print("Warning: '## GitHub Repository Settings' section not found in README.md.")
        return about, topics

    section_text = section_match.group(1)

    # Extract About: looks for "**About:**" or "About:"
    about_match = re.search(r"(?:\*\*About:\*\*|About:)\s*\n*(.*?)(?:\n\n|\n\*\*|\n\*|$)", section_text, re.DOTALL | re.IGNORECASE)
    if about_match:
        about = about_match.group(1).strip()
        # Clean markdown wrappers if any
        about = about.replace("\n", " ").strip()
    
    # Extract Topics: looks for "**Topics:**" or "Topics:"
    topics_match = re.search(r"(?:\*\*Topics:\*\*|Topics:)\s*\n*(.*?)(?:\n\n|\n\*\*|\n\*|$)", section_text, re.DOTALL | re.IGNORECASE)
    if topics_match:
        topics_line = topics_match.group(1)
        topics = re.findall(r"`([^`]+)`", topics_line)
    
    return about, topics

def github_api_request(owner, repo, endpoint, method, data=None, token=None):
    """Perform a request to the GitHub API using urllib."""
    url = f"https://api.github.com/repos/{owner}/{repo}{endpoint}"
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Python-Urllib-Github-Updater"
    }
    
    req_body = None
    if data is not None:
        req_body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    
    req = urllib.request.Request(url, data=req_body, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req) as res:
            res_data = res.read().decode("utf-8")
            return json.loads(res_data) if res_data else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8") if e.fp else ""
        print(f"HTTP Error {e.code}: {e.reason}")
        if err_body:
            try:
                err_json = json.loads(err_body)
                print(f"GitHub Message: {err_json.get('message')}")
                if "errors" in err_json:
                    print(f"GitHub Errors: {err_json.get('errors')}")
            except Exception:
                print(f"Raw response: {err_body}")
        raise e
    except Exception as e:
        print(f"Error during request: {e}")
        raise e

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Update GitHub Repository Description and Topics from README.md.")
    parser.add_argument("--token", help="GitHub Personal Access Token (PAT). Can also use GITHUB_TOKEN or GH_TOKEN env variables.")
    parser.add_argument("--owner", help="GitHub repository owner (default: extracted from git remote).")
    parser.add_argument("--repo", help="GitHub repository name (default: extracted from git remote).")
    parser.add_argument("--dry-run", action="store_true", help="Parse and show what would be updated without making API calls.")
    
    args = parser.parse_args()
    
    # 1. Determine Owner and Repo
    owner = args.owner
    repo = args.repo
    if not owner or not repo:
        detected_owner, detected_repo = get_git_repo_info()
        if not owner:
            owner = detected_owner
        if not repo:
            repo = detected_repo
            
    print(f"Target Repository: {owner}/{repo}")
    
    # 2. Parse README
    about, topics = parse_readme()
    if not about:
        print("Error: Could not extract 'About' section from README.md.")
        sys.exit(1)
    if not topics:
        print("Warning: No topics extracted from README.md.")

    print("\n--- Parsed settings from README.md ---")
    print(f"About:  {about}")
    print(f"Topics: {', '.join(topics)}")
    print("--------------------------------------\n")
    
    if args.dry_run:
        print("Dry run active. No API requests were sent.")
        return
        
    # 3. Retrieve Token
    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("Error: GitHub Access Token is required.")
        print("Please provide it via --token parameter or set GITHUB_TOKEN / GH_TOKEN environment variables.")
        sys.exit(1)
        
    # 4. Update About / Description
    print(f"Updating description (About) for {owner}/{repo}...")
    try:
        github_api_request(
            owner=owner,
            repo=repo,
            endpoint="",
            method="PATCH",
            data={"description": about},
            token=token
        )
        print("Successfully updated description!")
    except Exception:
        print("Failed to update description.")
        sys.exit(1)
        
    # 5. Update Topics / Tags
    if topics:
        print(f"\nUpdating topics for {owner}/{repo}...")
        try:
            github_api_request(
                owner=owner,
                repo=repo,
                endpoint="/topics",
                method="PUT",
                data={"names": topics},
                token=token
            )
            print("Successfully updated topics!")
        except Exception:
            print("Failed to update topics.")
            sys.exit(1)
    else:
        print("\nSkipping topics update (none found in README.md).")

if __name__ == "__main__":
    main()
