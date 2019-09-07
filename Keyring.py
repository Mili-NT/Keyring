from random import choice
from configparser import ConfigParser
import errno
import re
import requests
from os import getcwd, listdir, makedirs, mkdir
from os.path import isfile, join, isdir, exists, dirname
import shodan
from time import sleep
import codecs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# By Mili
# Python 3.6.0

#
# Global Variables
#
parser = ConfigParser()
curdir = getcwd()
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
    'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0']
baselink = 'https://github.com/'
baseraw = 'https://raw.githubusercontent.com/'
#
# Global Functions
#

def shodan_search(displaymode, page):
    print("Searching for Shodan keys...")
    shodan_pattern = r'\b[a-zA-Z0-9]{32}\b'
    pagetext = page.text
    keyset = []
    for k in re.findall(shodan_pattern, pagetext):
        keyset.append(k)
    if not keyset:
        print("no keys found")
    else:
        valid_paid_keys = {}
        valid_unpaid_keys = []
        for key in set(keyset):
            api = shodan.Shodan(key)
            try:
                keydata = api.info()
                usage_limits = keydata['usage_limits']
                if keydata['plan'] == 'dev' or keydata['plan'] == 'edu':
                    credits_tuple = (usage_limits['scan_credits'], usage_limits['query_credits'])
                    valid_paid_keys[key] = credits_tuple
                elif keydata['plan'] == 'oss':
                    valid_unpaid_keys.append(key)
            except Exception as e:
                print(f"{e}.")


        if displaymode == 's' or displaymode == 'b':
            shodan_output = f'{curdir}\\Output\\ShodanKeys.txt'
            if not exists(dirname(shodan_output)):
                try:
                    makedirs(dirname(shodan_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(shodan_output, 'a') as sofile:
                sofile.write('----------VALID KEYS----------')
                for pkey in valid_paid_keys.keys():
                    sofile.write(f"Key: {pkey}\nCredits (scan, query): {valid_paid_keys[pkey][0]}, {valid_paid_keys[pkey][1]}\n\n")
                sofile.write('----------UNPAID KEYS----------')
                for upkeys in set(valid_unpaid_keys):
                    sofile.write(f'Key: {upkeys}')
def github_search(displaymode, page):
    print("Searching for Github keys...")
    github_api = r"[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]"
    pagetext = page.text
    for k in re.findall(github_api, pagetext):
        if displaymode == 's' or 'b':
            github_output = f'{curdir}\\Output\\GithubPotentialKeys.txt'
            if not exists(dirname(github_output)):
                try:
                    makedirs(dirname(github_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(github_output, 'a') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def AWS_search(displaymode, page):
    print("Searching for AWS Access Keys...")
    aws_pattern = r"AKIA[0-9A-Z]{16}"
    pagetext = page.text
    for k in re.findall(aws_pattern, pagetext):
        if displaymode == 's' or 'b':
            aws_output = f'{curdir}\\Output\\AWSPotentialTokens.txt'
            if not exists(dirname(aws_output)):
                try:
                    makedirs(dirname(aws_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(aws_output, 'a') as gofile:
                gofile.write(f'Potential Tokens: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Token: {k}')
    print('\nWarning: High Severity Item Found\n')
def google_access_token_search(displaymode, page):
    print("Scanning for google access tokens...")
    pagetext = page.text
    gat_pattern = r'ya29.[0-9a-zA-Z_\\-]{68}'
    for k in re.findall(gat_pattern, pagetext):
        if displaymode == 's' or 'b':
            print('\nWarning: High Severity Item Found\n')
            gat_output = f'{curdir}\\Output\\GoogleAccessPotentialTokens.txt'
            if not exists(dirname(gat_output)):
                try:
                    makedirs(dirname(gat_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(gat_output, 'a') as gofile:
                gofile.write(f'Potential Token: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Token: {k}')
            print('\nWarning: High Severity Item Found\n')
def google_oauth_search(displaymode, page):
    print("Scanning for google OAUTH secrets...")
    pagetext = page.text
    gauth_pattern = r"(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")"
    for k in re.findall(gauth_pattern, pagetext):
        if displaymode == 's' or 'b':
            print('\nWarning: High Severity Item Found\n')
            gauth_output = f'{curdir}\\Output\\GoogleOAUTHSecrets.txt'
            if not exists(dirname(gauth_output)):
                try:
                    makedirs(dirname(gauth_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(gauth_output, 'a') as gofile:
                gofile.write(f'Potential Secret: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Secret: {k}')
            print('\nWarning: High Severity Item Found\n')
def google_api_search(displaymode, page):
    print("Scanning for google API keys...")
    pagetext = page.text
    google_api_pattern =  r'AIzaSy[0-9a-zA-Z_\\-]{33}'
    for k in re.findall(google_api_pattern, pagetext):
        if displaymode == 's' or 'b':
            gapi_output = f'{curdir}\\Output\\GoogleAPIPotentialKeys.txt'
            if not exists(dirname(gapi_output)):
                try:
                    makedirs(dirname(gapi_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(gapi_output, 'a') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def slack_api_search(displaymode, page):
    print("Scanning for slack API keys...")
    pagetext = page.text
    slack_api_pattern = r"xoxp-\\d+-\\d+-\\d+-[0-9a-f]+"
    for k in re.findall(slack_api_pattern, pagetext):
        if displaymode == 's' or 'b':
            sapi_output = f'{curdir}\\Output\\SlackAPIPotentialKeys.txt'
            if not exists(dirname(sapi_output)):
                try:
                    makedirs(dirname(sapi_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(sapi_output, 'a') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def slack_webhook_search(displaymode, page):
    print("Scanning for slack webhooks...")
    pagetext = page.text
    slack_webhook_pattern = r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
    for k in re.findall(slack_webhook_pattern, pagetext):
        if displaymode == 's' or 'b':
            slack_webhook_output = f'{curdir}\\Output\\SlackWebhooks.txt'
            if not exists(dirname(slack_webhook_output)):
                try:
                    makedirs(dirname(slack_webhook_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(slack_webhook_output, 'a') as gofile:
                gofile.write(f'Potential Hook: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Hook: {k}')
def slack_bot_search(displaymode, page):
    print("Scanning for slack bot tokens...")
    pagetext = page.text
    slack_bot_pattern = r"xoxb-\\d+-[0-9a-zA-Z]+"
    for k in re.findall(slack_bot_pattern, pagetext):
        if displaymode == 's' or 'b':
            slack_bot_output = f'{curdir}\\Output\\SlackBotPotentialTokens.txt'
            if not exists(dirname(slack_bot_output)):
                try:
                    makedirs(dirname(slack_bot_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(slack_bot_output, 'a') as gofile:
                gofile.write(f'Potential Token: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Token: {k}')
def nonspecific_api_search(displaymode, page):
    print("Scanning for nonspecific API keys...")
    pagetext = page.text
    nonspecific_pattern = r"[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]"
    for k in re.findall(nonspecific_pattern, pagetext):
        if displaymode == 's' or 'b':
            nonspecific_output = f'{curdir}\\Output\\NonspecificPotentialKeys.txt'
            if not exists(dirname(nonspecific_output)):
                try:
                    makedirs(dirname(nonspecific_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(nonspecific_output, 'a') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def discord_bot_search(displaymode, page):
    print("Scanning for discord bot tokens...")
    pagetext = page.text
    discord_token_pattern = r"([\w\-\.]+[\-\.][\w\-\.]+)"
    for k in re.findall(discord_token_pattern, pagetext):
        if displaymode == 's' or 'b':
            discord_bot_output = f'{curdir}\\Output\\DiscordBotPotentialTokens.txt'
            if not exists(dirname(discord_bot_output)):
                try:
                    makedirs(dirname(discord_bot_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(discord_bot_output, 'a') as gofile:
                gofile.write(f'Potential Token: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Token: {k}')
def discord_webhook_search(displaymode, page):
    print("Scanning for discord webhooks...")
    pagetext = page.text
    discord_webhook_pattern = r"(https:\/\/discordapp\.com\/api\/webhooks\/[\d]+\/[\w]+)"
    for k in re.findall(discord_webhook_pattern, pagetext):
        if displaymode == 's' or 'b':
            discord_webhook_output = f'{curdir}\\Output\\DiscordWebhooks.txt'
            if not exists(dirname(discord_webhook_output)):
                try:
                    makedirs(dirname(discord_webhook_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(discord_webhook_output, 'a') as gofile:
                gofile.write(f'Potential Hook: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Hook: {k}')
def discord_nitro_search(displaymode, page):
    print("Scanning for discord nitro links...")
    pagetext = page.text
    discord_nitro_pattern = r"(https:\/\/discord\.gift\/.+[a-z{1,16}])"
    for k in re.findall(discord_nitro_pattern, pagetext):
        if displaymode == 's' or 'b':
            discord_nitro_output = f'{curdir}\\Output\\DiscordNitroPotentialLinks.txt'
            if not exists(dirname(discord_nitro_output)):
                try:
                    makedirs(dirname(discord_nitro_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(discord_nitro_output, 'a') as gofile:
                gofile.write(f'Potential link: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential link: {k}')
def redis_search(displaymode, page):
    print("Scanning for Redis URLs...")
    pagetext = page.text
    redis_pattern = r'redis://[0-9a-zA-Z:@.\\-]+'
    for k in re.findall(redis_pattern, pagetext):
        if displaymode == 's' or 'b':
            redis_output = f'{curdir}\\Output\\RedisLinks.txt'
            if not exists(dirname(redis_output)):
                try:
                    makedirs(dirname(redis_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(redis_output, 'a') as gofile:
                gofile.write(f'Potential link: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential link: {k}')
    print('\nWarning: High Severity Item Found\n')
def ssh_keys_search(displaymode, page):
    print("Scanning for SSH Keys...")
    pagetext = page.text
    ssh_keys_identifiers = ["-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----"]
    for pattern in set(ssh_keys_identifiers):
        if pattern in pagetext:
            if displaymode == 's' or 'b':
                ssh_output = f'{curdir}\\Output\\SSHKeys.txt'
                if not exists(dirname(ssh_output)):
                    try:
                        makedirs(dirname(ssh_output))
                    except OSError as racecondition:
                        if racecondition.errno != errno.EEXIST:
                            raise
                with open(ssh_output, 'a') as gofile:
                    gofile.write(f'SSH Key: {pattern}\n')
            elif displaymode == 'p' or 'b':
                print(f'SSH Key: {pattern}')
            print('\nWarning: High Severity Item Found\n')
def heroku_search(displaymode, page):
    print("Scanning for Heroku API keys...")
    pagetext = page.text
    heroku_pattern = r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
    for k in re.findall(heroku_pattern, pagetext):
        if displaymode == 's' or 'b':
            heroku_output = f'{curdir}\\Output\\HerokuKeys.txt'
            if not exists(dirname(heroku_output)):
                try:
                    makedirs(dirname(heroku_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(heroku_output, 'a') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def facebook_OAUTH(displaymode, page):
    print("Scanning for facebook OAUTH secrets...")
    pagetext = page.text
    fauth_pattern = r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]"
    for k in re.findall(fauth_pattern, pagetext):
        if displaymode == 's' or 'b':
            print('\nWarning: High Severity Item Found\n')
            fauth_output = f'{curdir}\\Output\\FacebookOAUTHSecrets.txt'
            if not exists(dirname(fauth_output)):
                try:
                    makedirs(dirname(fauth_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(fauth_output, 'a') as gofile:
                gofile.write(f'Potential Secret: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Secret: {k}')
            print('\nWarning: High Severity Item Found\n')
def twilio_search(displaymode, page):
    print("Scanning for twilio keys...")
    pagetext = page.text
    twilio_pattern = r"SK[a-z0-9]{32}"
    for k in re.findall(twilio_pattern, pagetext):
        if displaymode == 's' or 'b':
            twilio_output = f'{curdir}\\Output\\TwilioKeys.txt'
            if not exists(dirname(twilio_output)):
                try:
                    makedirs(dirname(twilio_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(twilio_output, 'a') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')



def random_headers():
    return {'User-Agent': choice(user_agents),'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}
def connect(url):
    def print_connecterror():
        print(f"""
    Exception occurred: {e} 
    Possible causes: Poor/Non-functioning Internet connection or {url} is unreachable 
    Possible fixes: Troubleshoot internet connection or check status of {url}
            """)
    def print_timeouterror():
        print(f"""
    Exception occurred: {e}
    Possible causes: Too many requests made to {url}
    Possible fixes: Check firewall settings and check the status of {url}.
            """)
    def print_genericerror():
        print(f"""
    Exception occurred: {e}
            """)
    try:
        page = requests.get(url,headers=random_headers())
        return page
    except Exception as e:
        if e is requests.exceptions.ConnectionError:
            print_connecterror()
        elif e is requests.exceptions.Timeout:
            print_timeouterror()
        else:
            print_genericerror()
        return 'connection_failed'

def get_repos(profilelink):
    if profilelink.endswith('//'):
        profilelink = profilelink[:len(profilelink)-1]
    repos = profilelink + '?tab=repositories'
    repos = repos.replace(' ','')
    profilepage = connect(repos)
    soup = BeautifulSoup(profilepage.text, 'html.parser')
    hrefs = soup.findAll('a', href=True, itemprop="name codeRepository")
    repolist = []
    for h in hrefs:
        repolink = baselink + str(h['href'])
        repolist.append(repolink)
    return repolist
def traverse_repos(repolist, verbosity): # Here Be Recursion
    fileaddrs = []
    def spider_current_level(page):
        dirnames = []
        levelsoup = BeautifulSoup(page.text, 'html.parser')
        try:
            spans = levelsoup.findAll('span', {'class': "css-truncate css-truncate-target"})
            for s in spans:
                subtags = s.findAll('a', {'class': "js-navigation-open"}, href=True)
                for st in subtags:
                    if '/blob/' in st['href']:
                        lnk = st['href'].replace('blob/', '')
                        if verbosity == 'on':
                            print(f"file: {lnk}")
                        full = baseraw + lnk
                        fileaddrs.append(full)
                    else:
                        if verbosity == 'on':
                            print(f"dir: {st['href']}")
                        dirnames.append(st['href'])

            if len(dirnames) == 0:
                if verbosity == 'on':
                    print("Branch exhausted")
            else:
                for subdir in dirnames:
                    subdir_addr = baselink + subdir
                    subdir_page = connect(subdir_addr)
                    spider_current_level(subdir_page)

        except AttributeError:
            # TODO: find and fix
            print("Unusual file behavior detected, ending spidering with current resources...")
    for i in repolist:
        repopage = connect(i)
        spider_current_level(repopage)
    return fileaddrs
def search_execute(displaymode,page):
    shodan_search(displaymode, page)
    github_search(displaymode, page)
    AWS_search(displaymode, page)
    google_access_token_search(displaymode, page)
    google_oauth_search(displaymode, page)
    google_access_token_search(displaymode, page)
    google_api_search(displaymode, page)
    slack_bot_search(displaymode, page)
    slack_api_search(displaymode, page)
    slack_webhook_search(displaymode, page)
    nonspecific_api_search(displaymode, page)
    discord_bot_search(displaymode, page)
    discord_webhook_search(displaymode, page)
    discord_nitro_search(displaymode, page)
    redis_search(displaymode, page)
    ssh_keys_search(displaymode, page)
    heroku_search(displaymode, page)
    facebook_OAUTH(displaymode, page)
    twilio_search(displaymode, page)

def scrape(scrape_input_method, displaymode, limiter,repo_crawl, verbosity):
    if scrape_input_method.lower() == 'm':
        url = input("Enter the URL: ")
        urlpage = connect(url)
        if urlpage == 'connection failed':
            print("Connection to specified URL could not be established.")
            exit()
        else:
            print('Status: [200], Searching for API Keys...')
            if repo_crawl is False:
                search_execute(displaymode, urlpage)
            else:
                repository_list = get_repos(url)
                file_addresses = traverse_repos(repository_list, verbosity)
                executor = ThreadPoolExecutor(max_workers=len(file_addresses))
                for addr in set(file_addresses):
                    urlpage = connect(addr)
                    executor.submit(search_execute(displaymode,urlpage))
                    sleep(limiter)
            print("Scanning complete.")

    else:
        while True:
            url_file = input("Enter the full path to the input file: ")
            if isfile(url_file) is True:
                break
            else:
                print("No Such File Found.")
                continue
        with open(url_file) as ufile:
            count = 0
            for line in ufile.readlines():
                count += 1
                urlpage = connect(line.rstrip())
                if urlpage == 'connection failed':
                    print(f"[Line: {count}] Connection failed on host {line}")
                else:
                    search_execute(displaymode, urlpage)
                    sleep(limiter)


def load_config():

    while True:
        if isdir(f'{curdir}\\KRconfig') is False:
            print(f"Config directory not detected in {curdir}...")
            print(f"Please move KRconfig directory into {curdir}")
            cont = input('Continue? [y/n]: ')
            if cont.lower() == 'y':
                continue
            elif cont.lower() == 'n':
                exit()
            else:
                print("Invalid Input")
                continue
        else:
            break

    config_files = {}
    count = 0
    onlyfiles = [f for f in listdir(f'{curdir}\\KRconfig') if isfile(join(f'{curdir}\\KRconfig', f))]
    for file in onlyfiles:
        if file.endswith('.ini'):
            count += 1
            config_files[file] = count
    if count == 0:
        print("No config files detected, making default...")
        with codecs.open(f'{curdir}\\KRconfig\\defaultconfig.ini', 'w', 'utf-8') as dconf:
            dconf.write(
'''[initial_vars]
displaymode = b
[scraping_vars]
scrape_input_method = m
limiter = 5
repo_crawl = False
verbosity = off''')
        config_files['Default Configuration'] = 1
        count += 1
    for k in config_files.keys():
        print(f"[{config_files[k]}]: {k}")
    while True:
        try:
            load_choice = int(input("Select which config file to load: "))
            if load_choice > count:
                raise ValueError
            break
        except ValueError:
            print("Invalid Input. Please enter the integer that corresponds with the desired config file.")
            continue
    for k in config_files.keys():
        if load_choice == config_files[k]:
            selected_file = k

    parser.read(f"{curdir}\\KRconfig\\{selected_file}", encoding='utf-8')
    # Initial Variables
    displaymode = parser.get('initial_vars', 'displaymode')
    # Scraping Variables
    scrape_input_method = parser.get('scraping_vars', 'scrape_input_method')
    limiter = int(parser.get('scraping_vars', 'limiter'))
    repo_crawl = parser.get('scraping_vars', 'repo_crawl')
    if repo_crawl == str('True'):
        repo_crawl = True
    else:
        repo_crawl = False
    verbosity = parser.get('scraping_vars', 'verbosity')

    return displaymode,scrape_input_method,limiter,repo_crawl,verbosity
def manual_setup():
    while True:
        displaymode = input("[p]rint to screen, [s]ave to file, or [b]oth: ")
        if displaymode.lower() not in ['p','s','b']:
            print("Invalid Input")
            continue
        break

    while True:
        scrape_input_method = input("[m]anual input (single url) or load from [f]ile: ")
        if scrape_input_method.lower() not in ['m', 'f']:
            print("Invalid Input")
            continue
        break

    while True:
        try:
            limiter = int(input("Enter the time between requests, in seconds: "))
            if limiter < 0:
                continue
            break
        except ValueError:
            print("Invalid Input. Enter a positive integer.")
            continue

    print("\nIf provided links to one (or multiple) github profiles, Keyring can crawl all repositories for secrets.")
    print("However, this means Keyring WILL NOT FUNCTION CORRECTLY if provided links to other pages in the same text file.")
    print("Large profiles will also take a fairly long time, as Keyring fetches ALL files from ALL repos.\n")
    while True:
        repocrawlchoice = input("Enable repo crawling? [y]/[n]: ")
        if repocrawlchoice.lower() not in ['y','n']:
            print("Invalid Input.")
            continue
        elif repocrawlchoice.lower() == 'y':
            repo_crawl = True
            while True:
                print("Warning: Turning on verbosity will output a LOT when spidering large profiles.")
                verbosity = input("Select verbosity for spidering: [off]/[on]: ")
                if verbosity.lower() not in ['off','on']:
                    print("Invalid Input.")
                    continue
                else:
                    break
            break
        elif repocrawlchoice.lower() == 'n':
            repo_crawl = False
            verbosity = 'off'
            break

    while True:
        savechoice = input("Save choices as config file? [y]/[n]: ")
        if savechoice.lower() == 'n':
            break
        elif savechoice.lower() == 'y':
            while True:
                if isdir(f'{curdir}\\KRconfig') is False:
                    print(f"Config directory not detected in {curdir}...")
                    print(f"Making config directory...")
                    mkdir(f'{curdir}\\KRconfig')
                    break
                else:
                    break

            configname = input("Enter the name for this configuration: ")
            with open(f'{curdir}\\KRconfig\\{configname}.ini', 'w') as cfile:
                cfile.write(
f'''[initial_vars]
displaymode = {displaymode}
[scraping_vars]
scrape_input_method = {scrape_input_method}
limiter = {limiter}
repo_crawl = {repo_crawl}
verbosity = {verbosity}
''')
                break

    return displaymode,scrape_input_method,limiter,repo_crawl,verbosity
def main():
    while True:
        initchoice = input("[L]oad config file or [m]anually enter?: ")
        if initchoice.lower() == 'l':
            displaymode,scrape_input_method,limiter,repo_crawl,verbosity = load_config()
            if scrape_input_method == 'f':
                while True:
                    addressfile = input("Enter the full path to the address file: ")
                    if isfile(addressfile) is True:
                        break
                    else:
                        print("No such file found.")
                        continue
            break
        elif initchoice.lower() == 'm':
            displaymode,scrape_input_method,limiter,repo_crawl,verbosity = manual_setup()
            break
        else:
            print("Invalid Input.")
            continue

    scrape(scrape_input_method, displaymode, limiter, repo_crawl, verbosity)

if __name__ == '__main__':
    main()
