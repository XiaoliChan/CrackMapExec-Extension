import os
import uuid

from datetime import datetime
from cme.config import process_secret
from cme.connection import *
from cme.logger import CMEAdapter
from cme.helpers.logger import highlight
from cme.protocols.wmi.wmiexec_regout import WMIEXEC_REGOUT
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, WBEM_FLAG_FORWARD_ONLY, IWbemLevel1Login
from impacket.smbconnection import SMBConnection, SessionError

WMI_ERROR_STATUS = ['rpc_s_access_denied']

class wmi(connection):

    def __init__(self, args, db, host):
        #impacket only accept string type 'None'
        self.domain = None
        self.hash = ''
        self.lmhash = ''
        self.nthash = ''
        self.server_os = None

        connection.__init__(self, args, db, host)
    
    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            if self.login():
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'SMB',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname})
    
    def create_conn_obj(self):
        try:
            dcom = DCOMConnection(self.host, username="user", password=str(uuid.uuid4()), domain="fake", lmhash="", nthash="", oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            dcom.disconnect()
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                return True
        return False

    def enum_host_info(self):
        # smb no open, specify the domain
        if self.args.no_smb:
            self.domain = self.args.domain
        else:
            smb_conn = SMBConnection(self.host, self.host, None, timeout=5)
            no_ntlm = False

            try:
                smb_conn.login("", "")
            except BrokenPipeError as e:
                self.logger.fail(f"Broken Pipe Error while attempting to login: {e}")
            except Exception as e:
                if "STATUS_NOT_SUPPORTED" in str(e):
                    no_ntlm = True
                pass

            self.domain = smb_conn.getServerDNSDomainName() if not no_ntlm else self.args.domain
            self.hostname = smb_conn.getServerName() if not no_ntlm else self.host
            self.server_os = smb_conn.getServerOS()
            if isinstance(self.server_os.lower(), bytes):
                self.server_os = self.server_os.decode("utf-8")

            self.logger.extra["hostname"] = self.hostname

            if not self.domain:
                self.domain = self.hostname

            try:
                smb_conn.logoff()
            except:
                pass

            if self.args.domain:
                self.domain = self.args.domain
            if self.args.local_auth:
                self.domain = self.hostname

        self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def print_host_info(self):
        if self.args.no_smb:
            self.logger.extra['protocol'] = "WMI"
            self.logger.extra['port'] = self.args.port
            self.logger.display(u"Connecting to WMI {}".format(self.hostname))
        else:
            self.logger.extra['protocol'] = "SMB"
            self.logger.extra['port'] = "445"
            self.logger.display(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                            self.hostname,
                                                            self.domain))
            self.logger.extra['protocol'] = "WMI"
            self.logger.extra['port'] = self.args.port
            self.logger.display(u"Connecting to WMI {}".format(self.hostname))
        return True

    def plaintext_login(self, domain, username, password):
        self.password = password
        self.username = username
        self.domain = domain
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            out = u'{}\\{}:{} {}'.format(domain,
                                        self.username,
                                        self.password,
                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label'))))
            self.logger.success(out)
            dcom.disconnect()
            if not self.args.continue_on_success:
                return True
        except Exception as e:
            self.logger.fail((f"{self.domain}\\{self.username}:{process_secret(self.password)} ({str(e)})"), color=("red" if "rpc_s_access_denied" in str(e) else "magenta"))
            return False

    def hash_login(self, domain, username, ntlm_hash):
        lmhash = ''
        nthash = ''

        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash
        try:
            self.username = username
            self.password = ''
            self.domain = domain
            self.hash = ntlm_hash
 
            if lmhash: self.lmhash = lmhash
            if nthash: self.nthash = nthash

            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)

            out = u'{}\\{}:{} {}'.format(domain,
                                         self.username,
                                         ntlm_hash,
                                         highlight('({})'.format(self.config.get('CME', 'pwn3d_label'))))

            self.logger.success(out)
            dcom.disconnect()
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            self.logger.fail((f"{self.domain}\\{self.username}:{process_secret(self.nthash)} ({str(e)})"), color=("red" if "rpc_s_access_denied" in str(e) else "magenta"))
            return False

    def wmi_query(self):
        WQL = self.args.wmi_query
        if not WQL:
            self.logger.fail("Missing WQL syntax in wmi query!")
            return False
        self.logger.success('Executing WQL: {}'.format(WQL))
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login,IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin(self.args.namespace , NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery(WQL.strip('\n'))
        except Exception as e:
            self.logger.fail('Execute WQL error: {}'.format(e))
            iWbemServices.RemRelease()
            dcom.disconnect()
        else:
            records = []
            while True:
                try:
                    wmi_results = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                    record = wmi_results.getProperties()
                    records.append(record)
                    for k,v in record.items():
                        self.logger.highlight('{} => {}'.format(k,v['value']))
                    self.logger.highlight('')
                except Exception as e:
                    if str(e).find('S_FALSE') < 0:
                        raise e
                    else:
                        break
            iEnumWbemClassObject.RemRelease()
            iWbemServices.RemRelease()
            dcom.disconnect()
            return records

    def execute(self):
        command = self.args.execute
        if not command:
            self.logger.fail("Missing command in wmiexec!")
            return False
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            win32Process, _ = iWbemServices.GetObject('Win32_Process')
            executor = WMIEXEC_REGOUT(win32Process, iWbemServices, self.host, self.logger, self.args.interval_time)
            executor.execute_remote(command)
            dcom.disconnect()
        except Exception as e:
            self.logger.fail('Execute command error: {}'.format(e))
            iWbemServices.RemRelease()
            dcom.disconnect()