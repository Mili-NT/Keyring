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
#
# Patterns And Shiet
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
#
# Global Functions
# I know I should have made all of these one function, but didn't think of that until I got to the slack_bot_search one
# ¯\_(ツ)_/¯

def shodan_search(displaymode, page):
    print("Searching for Shodan keys...")
    shodan_pattern = r'\b[a-zA-Z0-9]{32}\b'
    pagetext = page.text
    keyset = []
    for k in re.findall(shodan_pattern, pagetext):
        keyset.append(k)
    if not keyset:
        print("no keys found")
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
        with open(shodan_output, 'w') as sofile:
            sofile.write('----------VALID KEYS----------')
            for pkey in valid_paid_keys.keys():
                sofile.write(f"Key: {pkey}\nCredits (scan, query): {valid_paid_keys[pkey][0]}, {valid_paid_keys[pkey][1]}\n\n")
            sofile.write('----------UNPAID KEYS----------')
            for upkeys in set(valid_unpaid_keys):
                sofile.write(f'Key: {upkeys}')
def github_search(displaymode, page):
    print("Searching for Github keys...")
    github_api = '^\w{1,40}$'
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
            with open(github_output, 'w') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def AWS_search(displaymode, page):
    print("Searching for AWS Access Keys...")
    aws_pattern = "AKIA[0-9A-Z]{16}"
    pagetext = page.text
    for k in re.findall(aws_pattern, pagetext):
        if displaymode == 's' or 'b':
            aws_output = f'{curdir}\\Output\\AWSPotentialKeys.txt'
            if not exists(dirname(aws_output)):
                try:
                    makedirs(dirname(aws_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(aws_output, 'w') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def google_access_token_search(displaymode, page):
    print("Scanning for google access tokens...")
    pagetext = page.text
    gat_pattern = 'ya29.[0-9a-zA-Z_\\-]{68}'
    for k in re.findall(gat_pattern, pagetext):
        if displaymode == 's' or 'b':
            gat_output = f'{curdir}\\Output\\GATPotentialKeys.txt'
            if not exists(dirname(gat_output)):
                try:
                    makedirs(dirname(gat_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(gat_output, 'w') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def google_api_search(displaymode, page):
    print("Scanning for google API keys...")
    pagetext = page.text
    google_api_pattern =  'AIzaSy[0-9a-zA-Z_\\-]{33}'
    for k in re.findall(google_api_pattern, pagetext):
        if displaymode == 's' or 'b':
            gapi_output = f'{curdir}\\Output\\GoogleAPIPotentialKeys.txt'
            if not exists(dirname(gapi_output)):
                try:
                    makedirs(dirname(gapi_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(gapi_output, 'w') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def slack_api_search(displaymode, page):
    print("Scanning for slack API keys...")
    pagetext = page.text
    slack_api_pattern = "xoxp-\\d+-\\d+-\\d+-[0-9a-f]+"
    for k in re.findall(slack_api_pattern, pagetext):
        if displaymode == 's' or 'b':
            sapi_output = f'{curdir}\\Output\\SlackAPIPotentialKeys.txt'
            if not exists(dirname(sapi_output)):
                try:
                    makedirs(dirname(sapi_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(sapi_output, 'w') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def slack_bot_search(displaymode, page):
    print("Scanning for slack bot tokens...")
    pagetext = page.text
    slack_bot_pattern = "xoxb-\\d+-[0-9a-zA-Z]+"
    for k in re.findall(slack_bot_pattern, pagetext):
        if displaymode == 's' or 'b':
            slack_bot_output = f'{curdir}\\Output\\SlackBotPotentialKeys.txt'
            if not exists(dirname(slack_bot_output)):
                try:
                    makedirs(dirname(slack_bot_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(slack_bot_output, 'w') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def discord_bot_search(displaymode, page):
    print("Scanning for discord bot tokens...")
    pagetext = page.text
    discord_token_pattern = "([\w\-\.]+[\-\.][\w\-\.]+)"
    for k in re.findall(discord_token_pattern, pagetext):
        if displaymode == 's' or 'b':
            discord_bot_output = f'{curdir}\\Output\\DiscordBotPotentialKeys.txt'
            if not exists(dirname(discord_bot_output)):
                try:
                    makedirs(dirname(discord_bot_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(discord_bot_output, 'w') as gofile:
                gofile.write(f'Potential Key: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential Key: {k}')
def discord_nitro_search(displaymode, page):
    print("Scanning for discord nitro links...")
    pagetext = page.text
    discordd_nitro_pattern = "(https?:\/\/)?(www\.)?(discord\.(gift))\/.+[a-z{1,16}]"
    for k in re.findall(discordd_nitro_pattern, pagetext):
        if displaymode == 's' or 'b':
            discord_nitro_output = f'{curdir}\\Output\\DiscordNitroPotentialLinks.txt'
            if not exists(dirname(discord_nitro_output)):
                try:
                    makedirs(dirname(discord_nitro_output))
                except OSError as racecondition:
                    if racecondition.errno != errno.EEXIST:
                        raise
            with open(discord_nitro_output, 'w') as gofile:
                gofile.write(f'Potential link: {k}\n')
        elif displaymode == 'p' or 'b':
            print(f'Potential link: {k}')

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
def scrape(scrape_input_method, displaymode, limiter):
    if scrape_input_method.lower() == 'm':
        url = input("Enter the URL: ")
        urlpage = connect(url)
        if urlpage == 'connection failed':
            print("Connection to specified URL could not be established.")
            exit()
        else:
            print('Status: [200], Searching for API Keys...')
            shodan_search(displaymode, urlpage)
            github_search(displaymode, urlpage)
            shodan_search(displaymode, urlpage)
            github_search(displaymode, urlpage)
            AWS_search(displaymode, urlpage)
            google_access_token_search(displaymode, urlpage)
            google_access_token_search(displaymode, urlpage)
            google_api_search(displaymode, urlpage)
            slack_bot_search(displaymode, urlpage)
            slack_api_search(displaymode, urlpage)
            discord_bot_search(displaymode, urlpage)
            discord_nitro_search(displaymode, urlpage)
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
                    shodan_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    github_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    AWS_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    google_access_token_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    google_access_token_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    google_api_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    slack_bot_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    slack_api_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    discord_bot_search(displaymode, urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
                    sleep(limiter)
                    discord_nitro_search(displaymode,urlpage)
                    print(f"Search complete, ratelimiting for {limiter} seconds")
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
limiter = 5''')
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

    return displaymode,scrape_input_method,limiter
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
''')
                break

    return displaymode,scrape_input_method,limiter
def main():
    while True:
        initchoice = input("[L]oad config file or [m]anually enter?: ")
        if initchoice.lower() == 'l':
            displaymode,scrape_input_method,limiter = load_config()
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
            displaymode,scrape_input_method,limiter = manual_setup()
            break
        else:
            print("Invalid Input.")
            continue

    scrape(scrape_input_method, displaymode, limiter)





if __name__ == '__main__':
    main()
