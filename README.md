# Keyring
Keyring is a tool to search a given URL for API Keys and other secrets.

## Current Keys:
- Shodan (Very High Confidence, checks validity and available credits with the shodan library)
- Github API (Low confidence)
- Slack (High Confidence, static characters)
- Slack Bot (High Confidence, static characters)
- Google API (High Confidence, static characters)
- Google Access Tokens (High Confidence, static characters)
- AWS Access Tokens (High Confidence, static characters)
- Discord Bot Tokens (High Confidence, static characters and substring sizes)
- Discord Nitro Links (High Confidence, static characters and substring sizes)
### TODO:
- Add more keys (please send me either a sample key or regex for anything you want added)
- get it working with github pages (or use the github API). High Priority.
