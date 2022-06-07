import socket
import argparse
import sys
import logging
from struct import pack, unpack
from impacket.examples.utils import parse_target
from impacket.structure import Structure
from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode
from impacket.smbconnection import SMBConnection, SessionError
from binascii import a2b_hex
from Cryptodome.Cipher import ARC4
from impacket import ntlm, version
from OpenSSL import SSL, crypto
from cme.connection import *
from cme.logger import CMEAdapter
from cme.helpers.logger import highlight
from io import StringIO

TDPU_CONNECTION_REQUEST  = 0xe0
TPDU_CONNECTION_CONFIRM  = 0xd0
TDPU_DATA                = 0xf0
TPDU_REJECT              = 0x50
TPDU_DATA_ACK            = 0x60

# RDP_NEG_REQ constants
TYPE_RDP_NEG_REQ = 1
PROTOCOL_RDP     = 0
PROTOCOL_SSL     = 1
PROTOCOL_HYBRID  = 2

# RDP_NEG_RSP constants
TYPE_RDP_NEG_RSP = 2
EXTENDED_CLIENT_DATA_SUPPORTED = 1
DYNVC_GFX_PROTOCOL_SUPPORTED   = 2

# RDP_NEG_FAILURE constants
TYPE_RDP_NEG_FAILURE                  = 3
SSL_REQUIRED_BY_SERVER                = 1
SSL_NOT_ALLOWED_BY_SERVER             = 2
SSL_CERT_NOT_ON_SERVER                = 3
INCONSISTENT_FLAGS                    = 4
HYBRID_REQUIRED_BY_SERVER             = 5
SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6

class TPKT(Structure):
    commonHdr = (
        ('Version','B=3'),
        ('Reserved','B=0'),
        ('Length','>H=len(TPDU)+4'),
        ('_TPDU','_-TPDU','self["Length"]-4'),
        ('TPDU',':=""'),
    )

class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator','B=len(VariablePart)+1'),
        ('Code','B=0'),
        ('VariablePart',':=""'),
    )

    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['VariablePart']=''

class CR_TPDU(Structure):
    commonHdr = (
        ('DST-REF','<H=0'),
        ('SRC-REF','<H=0'),
        ('CLASS-OPTION','B=0'),
        ('Type','B=0'),
        ('Flags','B=0'),
        ('Length','<H=8'),
    )

class DATA_TPDU(Structure):
    commonHdr = (
        ('EOT','B=0x80'),
        ('UserData',':=""'),
    )

    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['UserData'] =''

class RDP_NEG_REQ(CR_TPDU):
    structure = (
        ('requestedProtocols','<L'),
    )
    def __init__(self,data=None):
        CR_TPDU.__init__(self,data)
        if data is None:
            self['Type'] = TYPE_RDP_NEG_REQ

class RDP_NEG_RSP(CR_TPDU):
    structure = (
        ('selectedProtocols','<L'),
    )

class RDP_NEG_FAILURE(CR_TPDU):
    structure = (
        ('failureCode','<L'),
    )

class TSPasswordCreds(GSSAPI):
# TSPasswordCreds ::= SEQUENCE {
#         domainName  [0] OCTET STRING,
#         userName    [1] OCTET STRING,
#         password    [2] OCTET STRING
# }
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']
  
   def getData(self):
       ans = pack('B', ASN1_SEQUENCE)
       ans += asn1encode( pack('B', 0xa0) +
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['domainName'].encode('utf-16le'))) +
              pack('B', 0xa1) + 
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['userName'].encode('utf-16le'))) +
              pack('B', 0xa2) + 
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['password'].encode('utf-16le'))) )
       return ans 

class TSCredentials(GSSAPI):
# TSCredentials ::= SEQUENCE {
#        credType    [0] INTEGER,
#        credentials [1] OCTET STRING
# }
    def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']

    def getData(self):
     # Let's pack the credentials field
     credentials =  pack('B',0xa1) 
     credentials += asn1encode(pack('B',ASN1_OCTET_STRING) +
                    asn1encode(self['credentials']))

     ans = pack('B',ASN1_SEQUENCE) 
     ans += asn1encode( pack('B', 0xa0) +
            asn1encode( pack('B', 0x02) + 
            asn1encode( pack('B', self['credType']))) +
            credentials)
     return ans

class TSRequest(GSSAPI):
# TSRequest ::= SEQUENCE {
#	version     [0] INTEGER,
#       negoTokens  [1] NegoData OPTIONAL,
#       authInfo    [2] OCTET STRING OPTIONAL,
#	pubKeyAuth  [3] OCTET STRING OPTIONAL,
#}
#
# NegoData ::= SEQUENCE OF SEQUENCE {
#        negoToken [0] OCTET STRING
#}
#

   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']
       
   def fromString(self, data = None):
       next_byte = unpack('B',data[:1])[0]
       if next_byte != ASN1_SEQUENCE:
           raise Exception('SEQUENCE expected! (%x)' % next_byte)
       data = data[1:]
       decode_data, total_bytes = asn1decode(data) 

       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte !=  0xa0:
            raise Exception('0xa0 tag not found %x' % next_byte)
       decode_data = decode_data[1:]
       next_bytes, total_bytes = asn1decode(decode_data)                
       # The INTEGER tag must be here
       if unpack('B',next_bytes[0:1])[0] != 0x02:
           raise Exception('INTEGER tag not found %r' % next_byte)
       next_byte, _ = asn1decode(next_bytes[1:])
       self['Version'] = unpack('B',next_byte)[0]
       decode_data = decode_data[total_bytes:]
       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte == 0xa1:
           # We found the negoData token
           decode_data, total_bytes = asn1decode(decode_data[1:])
       
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
           decode_data, total_bytes = asn1decode(decode_data[1:])

           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
           decode_data, total_bytes = asn1decode(decode_data[1:])

           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != 0xa0:
               raise Exception('0xa0 tag not found %r' % next_byte)
           decode_data, total_bytes = asn1decode(decode_data[1:])
   
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           # the rest should be the data
           self['NegoData'] = decode_data2
           decode_data = decode_data[total_bytes+1:]

       if next_byte == 0xa2:
           # ToDo: Check all this
           # We found the authInfo token
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           self['authInfo'] = decode_data2
           decode_data = decode_data[total_bytes+1:]

       if next_byte == 0xa3:
           # ToDo: Check all this
           # We found the pubKeyAuth token
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           self['pubKeyAuth'] = decode_data2

   def getData(self):
     # Do we have pubKeyAuth?
     if 'pubKeyAuth' in self.fields:
         pubKeyAuth = pack('B',0xa3)
         pubKeyAuth += asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['pubKeyAuth']))
     else:
         pubKeyAuth = b''

     if 'authInfo' in self.fields:
         authInfo = pack('B',0xa2)
         authInfo+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['authInfo']))
     else: 
         authInfo = b''

     if 'NegoData' in self.fields:
         negoData = pack('B',0xa1) 
         negoData += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) + 
                    asn1encode(pack('B', 0xa0) + 
                    asn1encode(pack('B', ASN1_OCTET_STRING) + 
                    asn1encode(self['NegoData'])))))
     else:
         negoData = b''
     ans = pack('B', ASN1_SEQUENCE)
     ans += asn1encode(pack('B',0xa0) + 
            asn1encode(pack('B',0x02) + asn1encode(pack('B',0x02))) +
            negoData + authInfo + pubKeyAuth)
     
     return ans

class SPNEGOCipher:
    def __init__(self, flags, randomSessionKey):
        self.__flags = flags
        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.__clientSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey)
            self.__serverSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey,"Server")
            self.__clientSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey)
            self.__serverSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey,"Server")
            # Preparing the keys handle states
            cipher3 = ARC4.new(self.__clientSealingKey)
            self.__clientSealingHandle = cipher3.encrypt
            cipher4 = ARC4.new(self.__serverSealingKey)
            self.__serverSealingHandle = cipher4.encrypt
        else:
            # Same key for everything
            self.__clientSigningKey = randomSessionKey
            self.__serverSigningKey = randomSessionKey
            self.__clientSealingKey = randomSessionKey
            self.__clientSealingKey = randomSessionKey
            cipher = ARC4.new(self.__clientSigningKey)
            self.__clientSealingHandle = cipher.encrypt
            self.__serverSealingHandle = cipher.encrypt
        self.__sequence = 0

    def encrypt(self, plain_data):
        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            # When NTLM2 is on, we sign the whole pdu, but encrypt just
            # the data, not the dcerpc header. Weird..
            sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                    self.__clientSigningKey, 
                    self.__clientSealingKey,  
                    plain_data, 
                    plain_data, 
                    self.__sequence, 
                    self.__clientSealingHandle)
        else:
            sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                    self.__clientSigningKey, 
                    self.__clientSealingKey,  
                    plain_data, 
                    plain_data, 
                    self.__sequence, 
                    self.__clientSealingHandle)

        self.__sequence += 1

        return signature, sealedMessage

    def decrypt(self, answer):
        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            # TODO: FIX THIS, it's not calculating the signature well
            # Since I'm not testing it we don't care... yet
            answer, signature =  ntlm.SEAL(self.__flags, 
                    self.__serverSigningKey, 
                    self.__serverSealingKey,  
                    answer, 
                    answer, 
                    self.__sequence, 
                    self.__serverSealingHandle)
        else:
            answer, signature = ntlm.SEAL(self.__flags, 
                    self.__serverSigningKey, 
                    self.__serverSealingKey, 
                    answer, 
                    answer, 
                    self.__sequence, 
                    self.__serverSealingHandle)
            self.__sequence += 1

        return signature, answer

class rdp(connection):
    def __init__(self, args, db, host):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '        Method: ' + sys._getframe(0).f_code.co_name
        self.domain = ''
        self.hash = ''
        self.lmhash = ''
        self.nthash = ''
        self.server_os = None
        self.smbv1 = None
        
        #RDP Stuff
        

        #self.cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
        #if args.domain:
        #    self.domain = args.domain

        connection.__init__(self, args, db, host)
    
    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        rdp_parser = parser.add_parser('rdp', help="own stuff using RDP", parents=[std_parser, module_parser], conflict_handler='resolve')
        rdp_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        rdp_parser.add_argument("--port", type=int, default=3389, help="rdp port (default: 3389)")
        rdp_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        rdp_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        # For domain options
        dgroup = rdp_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

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
        self.logger = CMEAdapter(extra={'protocol': 'RDP',
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
            tpkt = TPKT()
            tpdu = TPDU()
            rdp_neg = RDP_NEG_REQ()
            rdp_neg['Type'] = TYPE_RDP_NEG_REQ
            rdp_neg['requestedProtocols'] = PROTOCOL_HYBRID | PROTOCOL_SSL
            tpdu['VariablePart'] = rdp_neg.getData()
            tpdu['Code'] = TDPU_CONNECTION_REQUEST
            tpkt['TPDU'] = tpdu.getData()
            s = socket.socket()
            s.connect((self.host,self.args.port))
            s.sendall(tpkt.getData())
            pkt = s.recv(8192)
            tpkt.fromString(pkt)
            tpdu.fromString(tpkt['TPDU'])
            cr_tpdu = CR_TPDU(tpdu['VariablePart'])
        except:
            return False
        else:
            if isinstance(cr_tpdu['Type'],int) is True:
                return True
            else:
                return False
    
    def enum_host_info(self):
        # smb no open, specify the domain
        smb_conn = SMBConnection(self.host, self.host, None, timeout=2)
        try:
            smb_conn.login('', '')
        except:
            pass
            
        self.domain    = smb_conn.getServerDNSDomainName()
        self.hostname  = smb_conn.getServerName()
        self.server_os = smb_conn.getServerOS()
        self.signing   = smb_conn.isSigningRequired() if self.smbv1 else smb_conn._SMBConnection._Connection['RequireSigning']
        self.os_arch   = self.get_os_arch()
        self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
        self.output_filename = self.output_filename.replace(":", "-")

        if not self.domain:
            self.domain = self.hostname

        #self.db.add_computer(self.host, self.hostname, self.domain, self.server_os)

        try:
            '''
                DC's seem to want us to logoff first, windows workstations sometimes reset the connection
                (go home Windows, you're drunk)
            '''
            self.conn.logoff()
        except:
            pass

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
            #Cred
            self.password = password
            self.username = username
            self.domain = domain
            lmhash = ''
            nthash = ''

            #RDP
            tpkt = TPKT()
            tpdu = TPDU()
            rdp_neg = RDP_NEG_REQ()
            rdp_neg['Type'] = TYPE_RDP_NEG_REQ
            rdp_neg['requestedProtocols'] = PROTOCOL_HYBRID | PROTOCOL_SSL
            tpdu['VariablePart'] = rdp_neg.getData()
            tpdu['Code'] = TDPU_CONNECTION_REQUEST
            tpkt['TPDU'] = tpdu.getData()
            s = socket.socket()
            s.connect((self.host,self.args.port))
            s.sendall(tpkt.getData())
            pkt = s.recv(8192)
            tpkt.fromString(pkt)
            tpdu.fromString(tpkt['TPDU'])
            cr_tpdu = CR_TPDU(tpdu['VariablePart'])
            
            # Switching to TLS now
            ctx = SSL.Context(SSL.TLSv1_2_METHOD)
            ctx.set_cipher_list(b'RC4,AES')
            tls = SSL.Connection(ctx,s)
            tls.set_connect_state()
            tls.do_handshake()

            # NTLMSSP stuff
            auth = ntlm.getNTLMSSPType1('','',True, use_ntlmv2 = True)

            ts_request = TSRequest()
            ts_request['NegoData'] = auth.getData()

            tls.send(ts_request.getData())
            buff = tls.recv(4096)
            ts_request.fromString(buff)

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, ts_request['NegoData'], self.username, self.password, self.domain, lmhash, nthash, use_ntlmv2 = True)

            server_cert =  tls.get_peer_certificate()
            pkey = server_cert.get_pubkey()
            dump = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkey)

            dump = dump[7:]
            dump = b'\x30'+ asn1encode(dump)

            cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
            signature, cripted_key = cipher.encrypt(dump)
            ts_request['NegoData'] = type3.getData()
            ts_request['pubKeyAuth'] = signature.getData() + cripted_key
            tls.send(ts_request.getData())
            buff = tls.recv(1024)
        
        except Exception as err:
            if str(err).find("denied") > 0:
                self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                        self.username,
                                                        self.password,
                                                        "Access Denied"))
                return False
            else:
                self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                        self.username,
                                                        self.password,
                                                        str(err)))
                return False
        else:
            ts_request = TSRequest(buff)
            signature, plain_text = cipher.decrypt(ts_request['pubKeyAuth'][16:])
            tsp = TSPasswordCreds()
            tsp['domainName'] = self.domain
            tsp['userName']   = self.username
            tsp['password']   = self.password
            tsc = TSCredentials()
            tsc['credType'] = 1 # TSPasswordCreds
            tsc['credentials'] = tsp.getData()

            signature, cripted_creds = cipher.encrypt(tsc.getData())
            ts_request = TSRequest()
            ts_request['authInfo'] = signature.getData() + cripted_creds
            tls.send(ts_request.getData())
            
            out = u'{}\\{}:{} {}'.format(domain,
                                        self.username,
                                        self.password,
                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label'))))
            self.logger.success(out)
            if not self.args.continue_on_success:
                return True
    
    def hash_login(self, domain, username, ntlm_hash):
        lmhash = ''
        nthash = ''

        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
            lmhash = a2b_hex(lmhash)
            nthash = a2b_hex(nthash)
        else:
            nthash = a2b_hex(ntlm_hash)
        try:
            #Cred
            self.password = ''
            self.username = username
            self.domain = domain

            #RDP
            tpkt = TPKT()
            tpdu = TPDU()
            rdp_neg = RDP_NEG_REQ()
            rdp_neg['Type'] = TYPE_RDP_NEG_REQ
            rdp_neg['requestedProtocols'] = PROTOCOL_HYBRID | PROTOCOL_SSL
            tpdu['VariablePart'] = rdp_neg.getData()
            tpdu['Code'] = TDPU_CONNECTION_REQUEST
            tpkt['TPDU'] = tpdu.getData()
            s = socket.socket()
            s.connect((self.host,self.args.port))
            s.sendall(tpkt.getData())
            pkt = s.recv(8192)
            tpkt.fromString(pkt)
            tpdu.fromString(tpkt['TPDU'])
            cr_tpdu = CR_TPDU(tpdu['VariablePart'])
            
            # Switching to TLS now
            ctx = SSL.Context(SSL.TLSv1_2_METHOD)
            ctx.set_cipher_list(b'RC4,AES')
            tls = SSL.Connection(ctx,s)
            tls.set_connect_state()
            tls.do_handshake()

            # NTLMSSP stuff
            auth = ntlm.getNTLMSSPType1('','',True, use_ntlmv2 = True)

            ts_request = TSRequest()
            ts_request['NegoData'] = auth.getData()

            tls.send(ts_request.getData())
            buff = tls.recv(4096)
            ts_request.fromString(buff)

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, ts_request['NegoData'], self.username, self.password, self.domain, lmhash, nthash, use_ntlmv2 = True)

            server_cert =  tls.get_peer_certificate()
            pkey = server_cert.get_pubkey()
            dump = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkey)

            dump = dump[7:]
            dump = b'\x30'+ asn1encode(dump)

            cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
            signature, cripted_key = cipher.encrypt(dump)
            ts_request['NegoData'] = type3.getData()
            ts_request['pubKeyAuth'] = signature.getData() + cripted_key
            tls.send(ts_request.getData())
            buff = tls.recv(1024)
        
        except Exception as err:
            if str(err).find("denied") > 0:
                self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                        self.username,
                                                        ntlm_hash,
                                                        "Access Denied"))
                return False
            else:
                self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                        self.username,
                                                        ntlm_hash,
                                                        str(err)))
                return False
        else:
            ts_request = TSRequest(buff)
            signature, plain_text = cipher.decrypt(ts_request['pubKeyAuth'][16:])
            tsp = TSPasswordCreds()
            tsp['domainName'] = self.domain
            tsp['userName']   = self.username
            tsp['password']   = self.password
            tsc = TSCredentials()
            tsc['credType'] = 1 # TSPasswordCreds
            tsc['credentials'] = tsp.getData()

            signature, cripted_creds = cipher.encrypt(tsc.getData())
            ts_request = TSRequest()
            ts_request['authInfo'] = signature.getData() + cripted_creds
            tls.send(ts_request.getData())
            
            out = u'{}\\{}:{} {}'.format(domain,
                                        self.username,
                                        ntlm_hash,
                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label'))))
            self.logger.success(out)
            if not self.args.continue_on_success:
                return True