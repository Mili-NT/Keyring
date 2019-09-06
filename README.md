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
- Redis URLs (High Confidence, static characters and unique substring)

## Severity Rating (1-10):
- Access Tokens (10: can result in direct compromise of related systems)
- Redis URLs (10: can lead to database breaches)
- Bot Tokens (6: can result in sensitive information being viewed, members being banned/kicked/etc.)
- API Keys (5: can result in either loss of credits or sensitive information being viewed)
- Nitro Links (2 or 0: If not intended for giveaway, can result in loss of 10 dollars.)

### TODO:
- Add more keys (please send me either a sample key or regex for anything you want added)
- get it working with github pages (or use the github API). High Priority.
