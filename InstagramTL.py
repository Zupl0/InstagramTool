import time,requests,random,pyfiglet,pickle
from user_agent import generate_user_agent
import os
import sys
import json
import re
import getpass
from datetime import datetime
from instabot import Bot
from colorama import Fore


red=Fore.RED
yellow=Fore.YELLOW
blue=Fore.BLUE
green=Fore.GREEN
cyan=Fore.CYAN
global x2,j
x2 = '[🖤] @zuplo - Twitter at @overachiever_me'
j = '''
[☑️] NEW USER:︎︎
'''
req=requests.session()
r=requests.session()

cache_dir = 'cache'
session_cache = '%s/session.txt' % (cache_dir)
followers_cache = '%s/followers.json' % (cache_dir)
following_cache = '%s/following.json' % (cache_dir)

instagram_url = 'https://www.instagram.com'
login_route = '%s/accounts/login/ajax/' % (instagram_url)
profile_route = '%s/%s/'
query_route = '%s/graphql/query/' % (instagram_url)
unfollow_route = '%s/web/friendships/%s/unfollow/'


session = requests.Session()
def login_IG():
    global password
    global username
    username=input('Enter the username of the account:')
    password =getpass.getpass('Enter the password of the account:')

    

def login():
    session.headers.update({
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.8',
        'Connection': 'keep-alive',
        'Content-Length': '0',
        'Host': 'www.instagram.com',
        'Origin': 'https://www.instagram.com',
        'Referer': 'https://www.instagram.com/',
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36'),
        'X-Instagram-AJAX': '7a3a3e64fa87',
        'X-Requested-With': 'XMLHttpRequest'
    })

    reponse = session.get(instagram_url)

    csrf = re.findall(r"csrf_token\":\"(.*?)\"", reponse.text)[0]
    if csrf:
        session.headers.update({
            'x-csrftoken': csrf
        })
    else:
        print("No csrf token found in cookies, maybe you are temp ban? Wait 1 hour and retry")
        return False

    time.sleep(random.randint(2, 6))

    post_data = {
        'username': username,
        'enc_password': '#PWD_INSTAGRAM_BROWSER:0:{}:{}'.format(int(datetime.now().timestamp()), password)
    }

    response = session.post(login_route, data=post_data, allow_redirects=True)
    response_data = json.loads(response.text)

    if 'two_factor_required' in response_data:
        print('Please disable 2-factor authentication to login.')
        sys.exit(1)

    if 'message' in response_data and response_data['message'] == 'checkpoint_required':
        print('Please check Instagram app for a security confirmation that it is you trying to login.')
        sys.exit(1)

    return response_data['authenticated']


# Not so useful, it's just to simulate human actions better
def get_user_profile(username):
    response = session.get(profile_route % (instagram_url, username))
    extract = re.search(r'window._sharedData = (.+);</script>', str(response.text))
    response = json.loads(extract.group(1))
    return response['entry_data']['ProfilePage'][0]['graphql']['user']


def get_followers_list():
    followers_list = []

    query_hash = '56066f031e6239f35a904ac20c9f37d9'
    variables = {
        "id":session.cookies['ds_user_id'],
        "include_reel":False,
        "fetch_mutual":False,
        "first":50
    }

    response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})
    while response.status_code != 200:
        time.sleep(600) # querying too much, sleeping a bit before querying again
        response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})

    print('.', end='', flush=True)

    response = json.loads(response.text)

    for edge in response['data']['user']['edge_followed_by']['edges']:
        followers_list.append(edge['node'])

    while response['data']['user']['edge_followed_by']['page_info']['has_next_page']:
        variables['after'] = response['data']['user']['edge_followed_by']['page_info']['end_cursor']

        time.sleep(2)

        response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})
        while response.status_code != 200:
            time.sleep(600) # querying too much, sleeping a bit before querying again
            response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})

        print('.', end='', flush=True)

        response = json.loads(response.text)

        for edge in response['data']['user']['edge_followed_by']['edges']:
            followers_list.append(edge['node'])

    return followers_list


def get_following_list():
    follows_list = []

    query_hash = 'c56ee0ae1f89cdbd1c89e2bc6b8f3d18'
    variables = {
        "id":session.cookies['ds_user_id'],
        "include_reel":False,
        "fetch_mutual":False,
        "first":50
    }

    response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})
    while response.status_code != 200:
        time.sleep(600) # querying too much, sleeping a bit before querying again
        response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})

    print('.', end='', flush=True)

    response = json.loads(response.text)

    for edge in response['data']['user']['edge_follow']['edges']:
        follows_list.append(edge['node'])

    while response['data']['user']['edge_follow']['page_info']['has_next_page']:
        variables['after'] = response['data']['user']['edge_follow']['page_info']['end_cursor']

        time.sleep(2)

        response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})
        while response.status_code != 200:
            time.sleep(600) # querying too much, sleeping a bit before querying again
            response = session.get(query_route, params={'query_hash': query_hash, 'variables': json.dumps(variables)})

        print('.', end='', flush=True)

        response = json.loads(response.text)

        for edge in response['data']['user']['edge_follow']['edges']:
            follows_list.append(edge['node'])

    return follows_list


def unfollow(user):
    if os.environ.get('DRY_RUN'):
        return True

    response = session.get(profile_route % (instagram_url, user['username']))
    time.sleep(random.randint(2, 4))

    # update header again, idk why it changed
    session.headers.update({
        'x-csrftoken': response.cookies['csrftoken']
    })

    response = session.post(unfollow_route % (instagram_url, user['id']))

    if response.status_code == 429: # Too many requests
        print('Temporary ban from Instagram. Grab a coffee watch a TV show and comeback later. I will try again...')
        return False

    response = json.loads(response.text)

    if response['status'] != 'ok':
        print('Error while trying to unfollow {}. Retrying in a bit...'.format(user['username']))
        print('ERROR: {}'.format(response.text))
        return False
    return True


def main():

    if os.environ.get('DRY_RUN'):
        print('DRY RUN MODE, script will not unfollow users!')

    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)

    if os.path.isfile(session_cache):
        with open(session_cache, 'rb') as f:
            session.cookies.update(pickle.load(f))
    else:
        is_logged = login()
        if is_logged == False:
            sys.exit('login failed, verify user/password combination')

        with open(session_cache, 'wb') as f:
            pickle.dump(session.cookies, f)

        time.sleep(random.randint(2, 4))

    connected_user = get_user_profile(username)

    print('You\'re now logged as {} ({} followers, {} following)'.format(connected_user['username'], connected_user['edge_followed_by']['count'], connected_user['edge_follow']['count']))

    time.sleep(random.randint(2, 4))

    following_list = []
    if os.path.isfile(following_cache):
        with open(following_cache, 'r') as f:
            following_list = json.load(f)
            print('following list loaded from cache file')

    if len(following_list) != connected_user['edge_follow']['count']:
        if len(following_list) > 0:
            print('rebuilding following list...', end='', flush=True)
        else:
            print('building following list...', end='', flush=True)
        following_list = get_following_list()
        print(' done')

        with open(following_cache, 'w') as f:
            json.dump(following_list, f)

    followers_list = []
    if os.path.isfile(followers_cache):
        with open(followers_cache, 'r') as f:
            followers_list = json.load(f)
            print('followers list loaded from cache file')

    if len(followers_list) != connected_user['edge_followed_by']['count']:
        if len(following_list) > 0:
            print('rebuilding followers list...', end='', flush=True)
        else:
            print('building followers list...', end='', flush=True)
        followers_list = get_followers_list()
        print(' done')

        with open(followers_cache, 'w') as f:
            json.dump(followers_list, f)

    followers_usernames = {user['username'] for user in followers_list}
    unfollow_users_list = [user for user in following_list if user['username'] not in followers_usernames]

    print('you are following {} user(s) who aren\'t following you:'.format(len(unfollow_users_list)))
    for user in unfollow_users_list:
        print(user['username'])

    if len(unfollow_users_list) > 0:
        print('Begin to unfollow users...')

        for user in unfollow_users_list:
            if not os.environ.get('UNFOLLOW_VERIFIED') and user['is_verified'] == True:
                print('Skipping {}...'.format(user['username']))
                continue

            time.sleep(random.randint(5, 10))

            print('Unfollowing {}...'.format(user['username']))
            while unfollow(user) == False:
                sleep_time = random.randint(1, 3) * 1000 # High number on purpose
                print('Sleeping for {} seconds'.format(sleep_time))
                time.sleep(sleep_time)

        print(' done')

def info_Getting():
	print("-------------------------------------")
	user = input("[?] Username of the Target:")
	url = "https://i.instagram.com:443/api/v1/users/lookup/"
	headers = {"Connection": "close", "X-IG-Connection-Type": "WIFI","mid":"XOSINgABAAG1IDmaral3noOozrK0rrNSbPuSbzHq","X-IG-Capabilities": "3R4=","Accept-Language": "ar-sa","Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
	"User-Agent": "Instagram 99.4.0 Filza_TweakPY (Filza_TweakPY)",
	"Accept-Encoding": "gzip, deflate"}
	data={"signed_body": "35a2d547d3b6ff400f713948cdffe0b789a903f86117eb6e2f3e573079b2f038.{\"q\":\"%s\"}" % user }
	req=requests.post(url, headers=headers, data=data)
	inf=req.json()
	print("-------------------------------------")
	print("[+] username:",user)
	print("-------------------------------------")
	print("[+] email sent:",inf['email_sent'])
	print("[+] sms sent:",inf['sms_sent'])
	print("[+] You search by:",inf['lookup_source'])
	print("[+] email:",inf['obfuscated_email'])
	print("[+] phone:",inf['obfuscated_phone'])
	print("[+] acc is private or not:",inf['user']['is_private'])
	print("[+] acc is verified or not:",inf['user']['is_verified'])
	print("[+] valid phone:",inf['has_valid_phone'])
	print("[+] can reset with email:",inf['can_email_reset'])
	print("[+] can reset with sms:",inf['can_sms_reset'])
	print("[+] any user like his name:",inf['multiple_users_found'])
	print("[+] full name:",inf['user']['full_name'])
	print("[+] can reset with wa:",inf['can_wa_reset'])
	print("[+] user id:",inf['user_id'])
	print("[+] the fb login option:",inf['fb_login_option'])
	print("-------------------------------------")
	print("[+] profile pic id :",inf['user']['profile_pic_id'])
	print("[+] profile pic url:",inf['user']['profile_pic_url'])
	print("-------------------------------------")


def sms_In():
	phone=input('[+] The phone Number : ')
	url='https://www.instagram.com/accounts/send_signup_sms_code_ajax/'
	head={
		'HOST': "www.instagram.com",
		'KeepAlive': 'True',
		'user-agent': generate_user_agent(),
		'Cookie': 'd9d491e11bf90765d9d491e11bf90765',
		'Accept': "*/*",
		'ContentType': "application/x-www-form-urlencoded",
		"X-Requested-With": "XMLHttpRequest",
		"X-IG-App-ID": "936619743392459",
		"X-Instagram-AJAX": "missing",
		"X-CSRFToken": "missing",
		"Accept-Language": "en-US,en;q=0.9"}   
	data={
		'client_id': "X5uC6wALAAF-Lw3oSZE9kuY0mP_9",
		'phone_number': phone,
		'phone_id': '',
		'big_blue_token': ''}
	while True:
		Sms_in = requests.post(url,headers=head, data=data)
		if 'Looks like your phone number may be incorrect.' in Sms_in.text:
			print('[!] Check Your Phone Number')
			exit()
		elif 'Please wait a few minutes before you try again.' in Sms_in.text:
			print('[!] Ban For Min [3/10]')			
			exit()
		elif 'true' in Sms_in.text:
			print( '[-] Done send sms')						
		else:
			print('[!] Error ..')
			exit()

def check_vaild_email():
	email_or_user=input("[?] Type The Email:\n>")
	url='https://www.instagram.com/accounts/account_recovery_send_ajax/'
	head={
			'Host': 'www.instagram.com',
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
			'Accept': '*/*',
			'Accept-Language': 'ar,en-US;q=0.7,en;q=0.3',
			'Accept-Encoding': 'gzip, deflate, br',
			'X-CSRFToken': '5o7PN96Y9Ln95EnlXN6t0pmCHDqdbect',
			'X-Instagram-AJAX': '11170428d971',
			'X-IG-App-ID': '936619743392459',
			'X-ASBD-ID': '437806',
			'X-IG-WWW-Claim': '0',
			'Content-Type': 'application/x-www-form-urlencoded',
			'X-Requested-With': 'XMLHttpRequest',
			'Content-Length': '103',
			'Origin': 'https://www.instagram.com',
			'Connection': 'keep-alive',
			'Referer': 'https://www.instagram.com/accounts/password/reset/',
			'Cookie': 'ig_did=7B796F1F-ADE7-429C-8ADB-9B131663E5E4; datr=2kDRYNWmjctteBSnOqogPrxv; csrftoken=5o7PN96Y9Ln95EnlXN6t0pmCHDqdbect; mid=YNIa4QALAAGoeESFP8axY9NfC9t3; ig_nrcb=1',
			'TE': 'Trailers'}
	data={"email_or_username":email_or_user,"recaptcha_challenge_field":"","flow":"","app_id":"","source_account_id":""}
	req=requests.post(url,headers=head,data=data)
	if 'No users found' in req.text:
		print("[-] NOT Linked to an acc on instagram")
	elif req.json()['status']=="ok":
		print(f"[+] Linked To an account on instagram")
		print(f"[+] Done send Link to [{req.json()['contact_point']}]")
		print("[?] Can recover with code :"+str(req.json()['can_recover_with_code']))
	else:
			print("Error Ban [min 5/10] ")


def insta_checker_without_list():
    count = 0
    user = ""
    length = int(5)
    chars = "qwertyuiopasdfghjklzxcvbnm1234567890_"
    use_checkers = open('id_token.txt', "r").read().splitlines()
    ID = use_checkers[0]
    token = use_checkers[1]
    while True:
        if count < 1000:
            count += 1
            for user in range(1):
                user = ""
                for item in range(length):
                    user += random.choice(chars)
            urlinsta = f'https://www.instagram.com/{user}'
            headerinsta = {
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
                'cache-control': 'max-age=0',
                'sec-ch-ua': '"Google Chrome";v="89","Chromium";v="89", ";Not A Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36'
            }
            send = req.get(urlinsta, headers=headerinsta)
            if send.status_code == 404:
                print(green+f"[✅] Available: {user}")
                tele = (f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={j}\n𖡃 𝚄𝚂𝙴𝚁: {user}\n\n{x2}')
                re = requests.post(tele)
                with open('Available.txt', 'a') as x:
                    tl = '[] NEW USER -->  '
                    x.write(tl + user + '\n')
            else:
                print(red+f"[❌] Not Available: {user}")
            time.sleep(1)
        else:
            break
def insta_checker_with_list():
    sl = 'user.txt'
    file = open(sl, 'r')
    use_checkers = open('id_token.txt', "r").read().splitlines()
    ID = use_checkers[0]
    token = use_checkers[1]
    while True:
        user = file.readline().split('\n')[0]
        urlinsta = f'https://www.instagram.com/{user}'
        headerinsta = {
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
                'cache-control': 'max-age=0',
                'sec-ch-ua': '"Google Chrome";v="89","Chromium";v="89", ";Not A Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36'
            }
        send = req.get(urlinsta, headers=headerinsta)
        if send.status_code == 404:
            print(green+f"[✅] Available: {user}")
            tele = (f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={j}\n𖡃 𝚄𝚂𝙴𝚁: {user}\n\n{x2}')
            re = requests.post(tele)
            with open('Available.txt', 'a') as x:
                tl = '[] NEW USER -->  '
                x.write(tl + user + '\n')
        else:
            print(red+f"[❌] Not Available: {user}")
        time.sleep(1)


def comments_insta():
    global tx,slp,go,headLG,datLG
    try:
        done=0
        b=Bot
        r = requests.session()
        user = input("User: ")
        pess = input("Password: ")
        tx = input("Your text: ")
        post = input("Post url: ")
        idd=b.get_media_id_from_link(self='',link=post)
        slp = int(7.1)
        urLG = "https://www.instagram.com/accounts/login/ajax/"
        headLG = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'content-length': '272',
        'content-type': 'application/x-www-form-urlencoded',
        'cookie': 'ig_did=F839D900-5ECC-4392-BCAD-5CBD51FB9228; mid=YChlyQALAAHp2POOp2lK_-ciAGlM; ig_nrcb=1; csrftoken=W4fsZmCjUjFms6XmKl1OAjg8v81jZt3r; ds_user_id=45872034997; shbid=6144; shbts=1614374582.8963153',
        'origin': 'https://www.instagram.com',
        'referer': 'https://www.instagram.com/accounts/login/',
        'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
        'x-csrftoken': 'W4fsZmCjUjFms6XmKl1OAjg8v81jZt3r',
        'x-ig-app-id': '936619743392459',
        'x-ig-www-claim': '0',
        'x-instagram-ajax': '790551e77c76',
        'x-requested-with': 'XMLHttpRequest'}
        datLG = {
        "username": user,
        "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:&:{pess}",
        "queryParams": "{}",
        "optIntoOneTap": "false"}
        go = r.post(urLG, headers=headLG, data=datLG)
        if ("userId") in go.text:
            print(green+f"""Connection successful[✅]""")
            sis = go.cookies['sessionid']
            urCOm = 'https://www.instagram.com/web/comments/{}/add/'.format(idd)
            hedCOM = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9',
            'content-length': '44',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-457B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid=' + sis,
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/p/CMmx4KOpnx6/',
            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
            'x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi',
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq',
            'x-instagram-ajax': '753ce878cd6d',
            'x-requested-with': 'XMLHttpRequest'}
            daCOM = {
                'comment_text': tx,
                'replied_to_comment_id': ''}
            while True:
                time.sleep(slp)
                ct = r.post(urCOm, headers=hedCOM, data=daCOM)
                if '"status":"ok"' in ct.text:
                    print(green+f'[✅] DONE SEND COMMENT [{tx}]\nconut [{done}]')
                    done += 1
                    if done==101:
                        break
                elif 'Please' in ct.text:
                    print(red+'\n[‼️] ERROR SEND COMMENT - BAN ')
                elif ("two_factor") in go.text:
                    print(red+'\n[⛔️] Binary verification \n')
                    break
                elif ("checkpoint_url") in go.text:
                    print(yellow+'\n[⚠️] Account Secure \n')
                    break
                else:
                    print(blue+'\n[✖️] The username or password or post id is wrong! \n')
                    break
    except:
        pass
def reports_insta():
    try:
        collo = input("user: ")
        kim = input("password: ")
        offender = input("Target: ")
        done = 0
        url = 'https://www.instagram.com/accounts/login/ajax/'
        headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'content-length': '296',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/',
            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
            'x-csrftoken': 'MPicCBRW0thEKbRdX9DhiTL6UB0nGtqV',
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': 'hmac.AR1Y1dEsDcV-xq-u_7U0XISuyjCpWSS-VvmOhVU2N6rp9zg7',
            'x-instagram-ajax': 'f65d2f981648',
            'x-requested-with': 'XMLHttpRequest'}
        data = {
            'username': f'{collo}',
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{kim}',
            'queryParams': '{}',
            'optIntoOneTap': 'false'}
        zuplo = r.post(url, headers=headers, data=data)
        if '"authenticated":true' in zuplo.text:
            print(green+f"""Connected succesfully[✅]""")
            r.headers.update({'x-csrftoken': zuplo.cookies['csrftoken']})
            sl = int(4.5)
            url_id = 'https://www.instagram.com/{}/?__a=1'.format(offender)
            req_id = r.get(url_id).json()
            user_id = str(req_id['logging_page_id'])
            viking = user_id.split('_')[1]
            while True:
                url_spam = 'https://www.instagram.com/users/{}/report/'.format(viking)
                data_spam = {
                'source_name': '',
                'reason_id': 1,
                'frx_context': ''}
                solo = r.post(url_spam, data=data_spam)
                print(f'[✅] DONE SPAM USER [{offender}]\nconut [{done}]')
                time.sleep(sl)
                done += 1
                if done == 101:
                    break
        elif ('checkpoint_required') in zuplo.text:
            print(yellow+f"""[⚠️] SECURE!!!""")
        elif ('"user":true,"authenticated":false') in zuplo.text:
            print(red+f"""[✖️] WRONG PASSWORD!!!""")
        elif zuplo.status_code == "429":
            print(red+f"""[⛔️] YOU HAVE BAN!""")
        elif ('"user":false') in zuplo.text:
            print(red+f"""[❗️] USERNAME WAS NOT FOUND!!!""")
        else:
            print(red+"""[‼️] ERROR_CODE 404!""")
    except:
        pass
#############################
print(yellow+f"author:{red}@zuplo\t{cyan}Twitter:{blue}@overachiever_me{green}")
choose=int(input(f"""
{red}1) - Insta Comments
2) - Insta Reports
3) - Instagram Checkers
4) - Instagram Email Checker
5) - Instagram Checker
6) - Save the ID and token for using Checkers (Only One Time You will do that)
{blue}
7) - Info about an Account (Enter Valid Account)
8) - Send message to Target Phone Number(Please start with +Country Code)
9) - Unfollow the Followers who dont Follow Back
\nSelect One:--> """))
if choose==1:
    comments_insta()
elif choose==2:
    reports_insta()
elif choose==3:
    choose7=int(input(f"""
    {cyan}
    1) instagram checker with list
    {red}
    2) instagram checker without list
    """))
    if choose7==1:
        insta_checker_with_list()
    elif choose7==2:
        insta_checker_without_list()
    else:
        exit('@zuplo')

elif choose==4:
    check_vaild_email()
elif choose==5:
    choose7=int(input(f"""
    {cyan}
    1) instagram checker with list
    {red}
    2) instagram checker without list
    """))
    if choose7==1:
        insta_checker_with_list()
    elif choose7==2:
        insta_checker_without_list()
    else:
        exit('@zuplo')
elif choose==6:
    ID=input("ID ->: ")
    token=input("token ->: ")
    with open('id_token.txt', 'a') as x:
        x.write(ID + "\n" + token)
    print(f"ID: {ID}\nTOKEN: {token}")
elif choose==7:
    info_Getting()
elif choose==8:
    sms_In()
elif choose==9:
    login_IG()
    main()    
else:
    exit("Wrong Input \n@zuplo")
