from argparse import _StoreTrueAction

def proto_args(parser, std_parser, module_parser):
    wmi_parser = parser.add_parser('wmi', help="own stuff using WMI", parents=[std_parser, module_parser], conflict_handler='resolve')
    wmi_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
    wmi_parser.add_argument("--port", default=135, type=int, metavar='PORT', help='WMI port (default: 135)')
    no_smb_arg = wmi_parser.add_argument("--no-smb", action=get_conditional_action(_StoreTrueAction), make_required=[], help='No smb connection')

    # For domain options
    dgroup = wmi_parser.add_mutually_exclusive_group()
    domain_arg = dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', default=None, type=str, help="Domain to authenticate to")
    dgroup.add_argument("--local-auth", action='store_true', help='Authenticate locally to each target')
    no_smb_arg.make_required = [domain_arg]

    egroup = wmi_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
    egroup.add_argument("-q", metavar='QUERY', dest='wmi_query',type=str, help='Issues the specified WMI query')
    egroup.add_argument("--namespace", metavar='NAMESPACE', type=str, default='root\\cimv2', help='WMI Namespace (default: root\\cimv2)')

    cgroup = wmi_parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument("-x", metavar='EXECUTE', dest='execute', type=str, help='Creates a new powershell process and executes the specified command with output')
    cgroup.add_argument("--interval-time", default=5 ,metavar='INTERVAL_TIME', dest='interval_time', type=int, help='Set interval time(seconds) when executing command, unrecommend set it lower than 5')

    return parser

def get_conditional_action(baseAction):
    class ConditionalAction(baseAction):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop('make_required', [])
            super(ConditionalAction, self).__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super(ConditionalAction, self).__call__(parser, namespace, values, option_string)

    return ConditionalAction