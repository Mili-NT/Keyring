import os
from random import choice

# (Name, isHighSeverity):pattern
patterns_dict = {
	("Github_API", False):r"[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]",
	("AWS_Token", True):r"AKIA[0-9A-Z]{16}",
	("google_token", True):r'ya29.[0-9a-zA-Z_\\-]{68}',
	("google_OAUTH", True):r"(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
	("Google_API", False):r'AIzaSy[0-9a-zA-Z_\\-]{33}',
	("Slack_API", False):r"xoxp-\\d+-\\d+-\\d+-[0-9a-f]+",
	("Slack_Webhook", False):r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
	("Slack_Bot_Token", False):r"xoxb-\\d+-[0-9a-zA-Z]+",
	("Generic_API", False):r"[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
	("Discord_Bot_Token", False):r"([\w\-\.]+[\-\.][\w\-\.]+)",
	("Discord_Webhook", False):r"(https:\/\/discordapp\.com\/api\/webhooks\/[\d]+\/[\w]+)",
	("Discord_Nitro", False):r"(https:\/\/discord\.gift\/.+[a-z{1,16}])",
	("Heroku_API", False):r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
	("Facebook_OAUTH", True):r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
	("Twilio_API", False):r"SK[a-z0-9]{32}",
}

user_agents = [
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'
]

def PrintSuccess(Msg):
	if os.name == 'nt':
		print('[+] ' + Msg)
	else:
		print('\033[1;32m[+]\033[1;m ' + Msg)

def PrintStatus(Msg):
	if os.name == 'nt':
		print('[*] ' + Msg)
	else:
		print('\033[1;34m[*]\033[1;m ' + Msg)

def PrintFailure(Msg):
	if os.name == 'nt':
		print('[-] ' + Msg)
	else:
		print('\033[1;31m[-]\033[1;m ' + Msg)

def PrintError(Msg):
	if os.name == 'nt':
		print('[!] ' + Msg)
	else:
		print('\033[1;31m[!]\033[1;m ' + Msg)

def PrintHighSeverity(Msg):
	if os.name == 'nt':
		print('[$] ' + Msg)
	else:
		print('\033[1;33m[!]\033[1;m ' + Msg)

def random_headers():
	return { 'User-Agent': choice(user_agents), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' }
