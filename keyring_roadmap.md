# Project Overview
https://github.com/Mili-NT/Keyring
## Project Details:
- Name: **Keyring**
- Category: **Security**
- Creator: **Mili**
- Maintainers: **KuteKetX**
## Project Purpose:
Keyring is a tool designed to prevent information leaks in published code.
It uses regular expressions and keywords to match high severity items such as Access Tokens, API Keys, and database secrets.
Keyring can recursively crawl Github profiles and code repositories, or scan any valid URL
## Project Intent:
Keyring was designed to work mainly with Github profile and repositories.
Developers often leave unintended secrets in code which can lead to severe compromise.
The tool was developed to detect these secrets and record their type and location.
## Current Features:
- 19 Supported secrets including SSH Keys, Database Credentials, webhooks, and authentication secrets.
- Multithreaded
- Shodan API key validation and credit checking
- Recursive spidering
- Configuration files
- Fully developed in a linux environment with cross-OS compatibility in mind
## Planned Features:
- More API keys and secrets
- More accurate regular expressions

### Project Insights:
- 25 Stars
- 4 Watchers
- 3 Forks
- 66 Commits Across 2 Branches
- 3 Contributers with 3000 Additions and 1200 Deletions
