# Keyring
Keyring is a tool to search a given URL for API Keys and other secrets.

## Current Keys:
- Shodan (Very High Confidence, checks validity and available credits with the shodan library)
- Github API (High confidence, static characters and unique substring)
- Slack (High Confidence, static characters)
- Slack Bot (High Confidence, static characters)
- Slack Webhook Links (High Confidence, static characters and unique substring)
- Google API (High Confidence, static characters)
- Google Access Tokens (High Confidence, static characters)
- Google OAUTH Secrets (High Confidence, unique substring)
- AWS Access Tokens (High Confidence, static characters)
- Discord Bot Tokens (High Confidence, static characters and substring sizes)
- Discord Webhook Links: (High Confidence, static characters and substring types)
- Discord Nitro Links (High Confidence, static characters and substring sizes)
- Redis URLs (High Confidence, static characters and unique substring)
- SSH Keys (High Confidence, static characters)
- Heroku API Keys (High Confidence, static characters and unique substring)
- Twilio API Keys (Medium Confidence, few static characters but static string size)
- Facebook OAUTH (High Confidence, static characters and unique substring)
- Non-specific API Keys (Medium Confidence, static format may exclude potential keys)

## Severity Rating (1-10):
- Access Tokens (10: can result in direct compromise of related systems)
- Redis URLs (10: can lead to potentially severe leaks)
- SSH Keys (9: can potentially lead to system access in systems with poorly configured access control)
- OAUTH Secrets (7: can disclose sensitive information or lead to credential theft)
- Bot Tokens and Webhooks (6: can result in sensitive information being viewed, members being banned/kicked/etc.)
- API Keys (5: can result in either loss of credits or sensitive information being viewed)
- Nitro Links (2 or 0: If not intended for giveaway, can result in neglibigle financial loss.)

### TODO:
- Add more keys (please send me either a sample key or regex for anything you want added)
- Bug fixes
