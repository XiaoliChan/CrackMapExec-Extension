import asyncio
import subprocess
import os

from datetime import datetime
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from aardwolf.connection import RDPConnection
from aardwolf.commons.target import RDPTarget
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.constants import asyauthSecret
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS

success_login_yes_rdp = "Authentication only, exit status 0"

status_dict = {
    'Account has been locked':['ERRCONNECT_ACCOUNT_LOCKED_OUT'],
    'Account has been disabled':['ERRCONNECT_ACCOUNT_DISABLED [0x00020012]'],
    'Account was expired':['0x0002000D','0x00000009'],
    'Failed to connect to server':['0x0002000C','0x00020006'],
    'Password expired':['0x0002000E','0x0002000F','0x00020013'],
    'RDP login failed':['0x00020009','0x00020014']
}

class xfreerdp(connection):

    def __init__(self, args, db, host):
        self.iosettings = RDPIOSettings()
        self.iosettings.supported_protocols = ""
        self.protoflags_nla = [SUPP_PROTOCOLS.SSL|SUPP_PROTOCOLS.RDP, SUPP_PROTOCOLS.SSL, SUPP_PROTOCOLS.RDP]
        self.protoflags = [SUPP_PROTOCOLS.SSL|SUPP_PROTOCOLS.RDP, SUPP_PROTOCOLS.SSL, SUPP_PROTOCOLS.RDP, SUPP_PROTOCOLS.SSL|SUPP_PROTOCOLS.HYBRID, SUPP_PROTOCOLS.SSL|SUPP_PROTOCOLS.HYBRID_EX]
        self.iosettings.channels = []
        self.output_filename = None
        self.domain = None
        self.server_os = None
        self.url = None
        self.nla = True
        self.hybrid = False

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
        if self.domain is None:
            self.logger.display("Probably old, doesn't not support HYBRID or HYBRID_EX" f" (nla:{self.nla})")
        else:
            self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})" f" (nla:{self.nla})")
        return True

    def create_conn_obj(self):
        self.target = RDPTarget(ip=self.host, domain="FAKE", timeout=1)
        self.auth = NTLMCredential(secret="pass", username="user", domain="FAKE", stype=asyauthSecret.PASS)

        self.check_nla()

        for proto in reversed(self.protoflags):
            try:
                self.iosettings.supported_protocols = proto
                self.conn = RDPConnection(
                    iosettings=self.iosettings,
                    target=self.target,
                    credentials=self.auth,
                )
                asyncio.run(self.connect_rdp())
            except OSError as e:
                if "Errno 104" not in str(e):
                    return False
            except Exception as e:
                if "TCPSocket" in str(e):
                    return False
                if "Reason:" not in str(e):
                    info_domain = self.conn.get_extra_info()
                    self.domain = info_domain["dnsdomainname"]
                    self.hostname = info_domain["computername"]
                    self.server_os = info_domain["os_guess"] + " Build " + str(info_domain["os_build"])
                    self.logger.extra["hostname"] = self.hostname

                    self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))
                    break

        if self.args.domain:
            self.domain = self.args.domain

        if self.args.local_auth:
            self.domain = self.hostname

        self.target = RDPTarget(
            ip=self.host,
            hostname=self.hostname,
            domain=self.domain,
            dc_ip=self.domain,
            timeout=1,
        )

        return True

    def check_nla(self):
        for proto in self.protoflags_nla:
            try:
                self.iosettings.supported_protocols = proto
                self.conn = RDPConnection(
                    iosettings=self.iosettings,
                    target=self.target,
                    credentials=self.auth,
                )
                asyncio.run(self.connect_rdp())
                if str(proto) == "SUPP_PROTOCOLS.RDP" or str(proto) == "SUPP_PROTOCOLS.SSL" or str(proto) == "SUPP_PROTOCOLS.SSL|SUPP_PROTOCOLS.RDP":
                    self.nla = False
                    return
            except Exception as e:
                pass

    async def connect_rdp(self):
        _, err = await self.conn.connect()
        if err is not None:
            raise err

    def plaintext_login(self, domain, username, password):
        try:
            connection = subprocess.Popen("xfreerdp /v:'%s' /port:%s +auth-only /d:%s /u:%s /p:\"%s\" /sec:nla"
                                        " /cert-ignore /tls-seclevel:0 /timeout:80000" % (self.host, self.args.port ,domain, username, password), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read()
            output_info = connection.stdout.read()
            if success_login_yes_rdp in output_error.decode('utf-8'):
                self.admin_privs = True
                self.logger.success(u'{}\\{}:{} {}'.format(domain,
                                                        username,
                                                        password,
                                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            else:
                for k,v in status_dict.items():
                    if any(single_word in output_error.decode('utf-8') for single_word in v):
                        self.logger.fail(u'{}\\{}:{} {}'.format(domain,
                                                    username,
                                                    password,
                                                    '({})'.format(k)),
                                                    color='red')
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            print(e)

    def hash_login(self, domain, username, ntlm_hash):
        try:
            connection = subprocess.Popen("xfreerdp /v:'%s' /port:%s +auth-only /d:%s /u:%s /p:'' /pth:\"%s\" /sec:nla"
                                        " /cert-ignore /tls-seclevel:0 /timeout:80000" % (self.host, self.args.port ,domain, username, ntlm_hash), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read()
            output_info = connection.stdout.read()
            if success_login_yes_rdp in output_error.decode('utf-8'):
                self.admin_privs = True
                self.logger.success(u'{}\\{}:{} {}'.format(domain,
                                                        username,
                                                        ntlm_hash,
                                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            else:
                for k,v in status_dict.items():
                    if any(single_word in output_error.decode('utf-8') for single_word in v):
                        self.logger.fail(u'{}\\{}:{} {}'.format(domain,
                                                    username,
                                                    ntlm_hash,
                                                    '({})'.format(k)),
                                                    color='red')
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            print(e)
