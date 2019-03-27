
# suppress annoying warnings
import warnings
warnings.filterwarnings(action='ignore',module='.*paramiko.*')

# import pwnlib
from pwn import ssh

# password cache
from passcache import PasswordCache

# logging lib
from logzero import logger, loglevel

# import regex lib
import re

# functions
def info(msg):
    logger.info(msg)
    print()

# Bandit Class
class Bandit(object):
    URL = 'bandit.labs.overthewire.org'
    PORT = 2220

    @staticmethod
    def run():
        passcache = PasswordCache('./bandit.json')

        max_level = 34

        last_pass = 'bandit0'

        hack_level = 0

        for level in range(1, (max_level+1)):
            hack_level = (level - 1)

            try:
                hack_func = getattr(Bandit, 'level%s' % hack_level)
            except AttributeError:
                break

            ssh_pass = passcache.get('level%s' % level)

            if ssh_pass:
                last_pass = ssh_pass
                continue

            if not last_pass:
                raise Exception('No password for level %s' % hack_level)

            info('Hacking level%s..' % hack_level)

            shell = ssh(
                'bandit%s' % hack_level,
                host=Bandit.URL,
                port=Bandit.PORT,
                password=last_pass
            )

            new_ssh_pass = hack_func(shell)

            shell.close()

            if new_ssh_pass:
                info('Found level%s password: %s' % (level, new_ssh_pass))
                passcache.write_pass('level%s' % level, new_ssh_pass)
                last_pass = new_ssh_pass
            else:
                last_pass = None

        if level < max_level:
            info('Highest level reached: %s / %s' % (hack_level, max_level))
        else:
            info('DONE!')

    @staticmethod
    def level0(shell):
        level1_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat readme')
        level1_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level1_password

    @staticmethod
    def level1(shell):
        level2_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat ./-')
        level2_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level2_password

    @staticmethod
    def level2(shell):
        level3_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat ./spaces\ in\ this\ filename')
        level3_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level3_password

    @staticmethod
    def level3(shell):
        level4_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat ./inhere/.hidden')
        level4_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level4_password

    @staticmethod
    def level4(shell):
        level5_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('find ./inhere -type f -exec egrep -o "^\w{32}$" "{}" \;')
        level5_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level5_password

    @staticmethod
    def level5(shell):
        level6_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('find ./inhere -type f -exec egrep -o "^\w{32}$" "{}" \;')
        level6_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level6_password

    @staticmethod
    def level6(shell):
        level7_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat $(find / -user bandit7 -group bandit6 -size 33c 2>/dev/null)')
        level7_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level7_password

    @staticmethod
    def level7(shell):
        level8_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat ./data.txt | grep millionth | egrep -o "\w{32}"')
        level8_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level8_password

    @staticmethod
    def level8(shell):
        level9_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('sort data.txt | uniq -u')
        level9_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level9_password

    @staticmethod
    def level9(shell):
        level10_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('strings data.txt | grep === | egrep -o "\w{32}"')
        level10_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level10_password

    @staticmethod
    def level10(shell):
        level11_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat data.txt | base64 -d | egrep -o "\w{32}"')
        level11_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level11_password

    @staticmethod
    def level11(shell):
        level12_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('python -c "print(open(\'./data.txt\').read().decode(\'rot13\'))" | egrep -o "\w{32}"')
        level12_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level12_password

    @staticmethod
    def level12(shell):
        level13_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        folder = '/tmp/hellobye123'

        sh.sendline('mkdir -p %s' % folder)
        sh.sendline('cd %s' % folder)
        sh.sendline('cp ~/data.txt ./data.bin.orig')
        sh.sendline('xxd -r ./data.bin.orig > data.bin')

        sh.recvuntil('$ ', timeout=3)

        while True:
            sh.sendline('file ./data.bin')
            filetype = sh.recvline().decode('utf8').strip()
            sh.recvuntil('$ ')

            if 'gzip compressed data' in filetype:
                sh.sendline('mv ./data.bin ./data.bin.gz')
                sh.sendline('gunzip ./data.bin.gz')
            elif 'bzip2 compressed data' in filetype:
                sh.sendline('mv ./data.bin ./data.bin.bz2')
                sh.sendline('bunzip2 ./data.bin.bz2')
            elif 'POSIX tar' in filetype:
                sh.sendline('mv ./data.bin ./data.bin.tar')
                sh.recvuntil('$ ')
                sh.sendline('tar xvf ./data.bin.tar')
                new_file = sh.recvline().decode('utf8').strip()
                sh.sendline('mv %s ./data.bin' % new_file)
            elif 'ASCII text' in filetype:
                # get the password
                sh.sendline('cat ./data.bin | egrep -o "\w{32}"')
                level13_password = sh.recvline().decode('utf8').strip()
                break

        # close the shell
        sh.close()

        return level13_password

    @staticmethod
    def level13(shell):
        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -q -i sshkey.private -l bandit14 0 cat /etc/bandit_pass/bandit14')
        level14_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level14_password

    @staticmethod
    def level14(shell):
        level15_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('echo "4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e" | nc 0 30000 | egrep -o "\w{32}"')
        level15_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level15_password

    @staticmethod
    def level15(shell):
        level16_password = None

        # wait for prompt
        sh = shell.run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('echo "BfMYroe26WYalil77FoDi9qh59eK5xNr" | openssl s_client -connect 0:30001 -quiet 2>/dev/null | egrep -o "\w{32}"')
        level16_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level16_password