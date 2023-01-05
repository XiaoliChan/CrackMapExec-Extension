import logging
import asyncio
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
import subprocess
import sys

from aardwolf import logger
from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
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

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        xfreerdp_parser = parser.add_parser('xfreerdp', help="own stuff using RDP", parents=[std_parser, module_parser])
        xfreerdp_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        xfreerdp_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        xfreerdp_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        xfreerdp_parser.add_argument("--port", type=int, default=3389, help="Custom RDP port")

        dgroup = xfreerdp_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

        return parser

    def proto_flow(self):
        if self.create_conn_obj():
            self.proto_logger()
            self.print_host_info()
            if self.login():
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'RDP',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname})

    def print_host_info(self):
        if self.domain == None:
            self.logger.info(u"Probably old, doesn't not support HYBRID or HYBRID_EX (nla:{})".format(self.nla))
        else:
            self.logger.info(u"{} (name:{}) (domain:{}) (nla:{})".format(self.server_os,
                                                                self.hostname,
                                                                self.domain,
                                                                self.nla))

    def create_conn_obj(self):
        self.check_nla()
        for proto in reversed(self.protoflags):
            try:
                self.iosettings.supported_protocols = proto
                self.url = 'rdp+ntlm-password://FAKE\\user:pass@' + self.host + ':' + str(self.args.port)
                asyncio.run(self.connect_rdp(self.url))
            except OSError as e:
                if "Errno 104" not in str(e):
                    return False
            except Exception as e:
                if "TCPSocket" in str(e):
                    return False
                if "Reason:" not in str(e):
                    info_domain = self.conn.get_extra_info()
                    self.domain    = info_domain['dnsdomainname']
                    self.hostname  = info_domain['computername']
                    self.server_os = info_domain['os_guess'] + " Build " + str(info_domain['os_build'])
                    self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
                    self.output_filename = self.output_filename.replace(":", "-")
                    break

        if self.args.domain:
            self.domain = self.args.domain
        
        if self.args.local_auth:
            self.domain = self.hostname

        return True

    def check_nla(self):
        for proto in self.protoflags_nla:
            try:
                self.iosettings.supported_protocols = proto
                self.url = 'rdp+ntlm-password://FAKE\\user:pass@' + self.host + ':' + str(self.args.port)
                asyncio.run(self.connect_rdp(self.url))
                if str(proto) == "SUPP_PROTOCOLS.RDP" or str(proto) == "SUPP_PROTOCOLS.SSL" or str(proto) == "SUPP_PROTOCOLS.SSL|SUPP_PROTOCOLS.RDP":
                    self.nla = False
                    return
            except:
                pass

    async def connect_rdp(self, url):
        connectionfactory = RDPConnectionFactory.from_url(url, self.iosettings)
        self.conn = connectionfactory.create_connection_newtarget(self.host, self.iosettings)
        _, err = await self.conn.connect()
        if err is not None:
            raise err
        return True

    def plaintext_login(self, domain, username, password):
        try:
            connection = subprocess.Popen("xfreerdp /v:'%s' /port:%s +auth-only /d:%s /u:%s /p:\"%s\" /sec:nla"
                                        " /cert-ignore" % (self.host, self.args.port ,domain, username, password), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
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
                        self.logger.error(u'{}\\{}:{} {}'.format(domain,
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
                                        " /cert-ignore" % (self.host, self.args.port ,domain, username, ntlm_hash), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
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
                        self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                    username,
                                                    ntlm_hash,
                                                    '({})'.format(k)),
                                                    color='red')
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            print(e)
