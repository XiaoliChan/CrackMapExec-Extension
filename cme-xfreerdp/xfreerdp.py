import uuid, subprocess, os, re

from datetime import datetime
from termcolor import colored

from cme.connection import *
from cme.logger import CMEAdapter
from cme.config import process_secret
from cme.config import host_info_colors

success_flag = "Authentication only, exit status 0"

status_dict = {
    '(Account has been locked)':['ERRCONNECT_ACCOUNT_LOCKED_OUT'],
    '(Account has been disabled)':['ERRCONNECT_ACCOUNT_DISABLED [0x00020012]'],
    '(Account was expired)':['0x0002000D','0x00000009'],
    '(Not support NLA)':['ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED [0x0002000C]'],
    '(Password expired)':['0x0002000E','0x0002000F','0x00020013'],
    '(RDP login failed)':['0x00020009','0x00020014'],
    'Failed':['Resource temporarily unavailable', 'Broken pipe', 'ERRCONNECT_CONNECT_FAILED [0x00020006]', 'Connection timed out', 'Connection reset by peer']
}

class xfreerdp(connection):

    def __init__(self, args, db, host):
        self.output_filename = None
        self.domain = None
        self.nla = False

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "XFREERDP",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname,
            }
        )
    
    def print_host_info(self):
        nla = colored(f"nla:{self.nla}", host_info_colors[3], attrs=['bold']) if self.nla else colored(f"nla:{self.nla}", host_info_colors[2], attrs=['bold'])
        if not self.nla:
            self.logger.display(f"Old version OS which means not support NLA (name:{self.host}) {nla}")
        else:
            self.logger.display(f"(name:{self.hostname}) {nla}")
        return True

    def create_conn_obj(self):
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.args.port} +auth-only /d:"{str(uuid.uuid4())}" /u:"{str(uuid.uuid4())}" /p:"{str(uuid.uuid4())}" /cert-tofu /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read().decode('utf-8')
            if any(single_word in output_error for single_word in status_dict['Failed']):
                return False
            else:
                CN_match = re.search(r'CN = (\S+)', output_error)
                if CN_match:
                    hostname = CN_match.group(1)
                    self.nla = True
                    self.hostname = hostname
                    self.logger.extra["hostname"] = hostname
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
            output_error = connection.stderr.read().decode('utf-8')
            if success_flag in output_error:
                self.admin_privs = True
                self.logger.success(f"{domain}\\{username}:{process_secret(password)} {self.mark_pwned()}")
            else:
                for k,v in status_dict.items():
                    if any(single_word in output_error for single_word in v):
                        self.logger.fail(f"{domain}\\{username}:{process_secret(password)} {k}")
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            self.logger.error(str(e))

    def hash_login(self, domain, username, ntlm_hash):
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.args.port} +auth-only /d:"{domain}" /u:"{username}" /p:"" /pth:{ntlm_hash} /sec:nla /cert-ignore /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read().decode('utf-8')
            if success_flag in output_error:
                self.admin_privs = True
                self.logger.success(f"{domain}\\{username}:{process_secret(ntlm_hash)} {self.mark_pwned()}")
            else:
                for k,v in status_dict.items():
                    if any(single_word in output_error for single_word in v):
                        self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} {k}")
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            self.logger.error(str(e))
