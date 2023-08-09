#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
# Author: xiaolichan
# Link: https://github.com/XiaoliChan/wmiexec-RegOut/blob/main/wmiexec-regOut.py
# Note: windows version under NT6 not working with this command execution way
#       https://github.com/XiaoliChan/wmiexec-RegOut/blob/main/wmiexec-reg-sch-UnderNT6-wip.py -- WIP
# 
# Description: 
#   For more details, please check out my repository.
#   https://github.com/XiaoliChan/wmiexec-RegOut
#
# Workflow:
#   Stage 1:
#       cmd.exe /Q /c {command} > C:\windows\temp\{random}.txt (aka command results)
#
#   Stage 2:
#       powershell convert the command results into base64, and save it into C:\windows\temp\{random2}.txt (now the command results was base64 encoded)
#
#   Stage 3:
#       Create registry path: HKLM:\Software\Classes\hello, then add C:\windows\temp\{random2}.txt into HKLM:\Software\Classes\hello\{NewKey}
#
#   Stage 4:
#       Remove anythings which in C:\windows\temp\
#
#   Stage 5:
#       WQL query the HKLM:\Software\Classes\hello\{NewKey} and get results, after the results(base64 strings) retrieved, removed

import time
import uuid
import base64

OUTPUT_FILENAME = '__' + str(time.time())

class WMIEXEC_REGOUT:
    def __init__(self, win32Process, iWbemServices, address, logger, interval_time):
        self.command = ''
        self.logger = logger
        self.address = address
        self.interval_time = interval_time
        self.__shell = 'cmd.exe /Q /c '
        #self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__pwsh = 'powershell.exe -Enc '
        self.__win32Process = win32Process
        self.iWbemServices = iWbemServices
        self.__pwd = str('C:\\')

    def encodeCommand(self, data):
        data = '$ProgressPreference="SilentlyContinue";' + data
        data = self.__pwsh + base64.b64encode(data.encode('utf-16le')).decode()
        return data

    def execute_remote(self, data):
        self.command = data
        # Save result as txt file
        self.logger.info("Executing command: \" %s \""%data)
        resultTXT = "C:\\windows\\temp\\" + str(uuid.uuid4()) + ".txt"
        data = data + " > " + resultTXT
        command = self.__shell + self.encodeCommand(data)
        self.__win32Process.Create(command, self.__pwd, None)
        self.logger.info("Waiting {}s for command completely executed.".format(self.interval_time))
        time.sleep(self.interval_time)
        
        # Convert result to base64 strings
        self.logger.info("Save file to: " + resultTXT)
        keyName = str(uuid.uuid4())
        data = """[convert]::ToBase64String((Get-Content -path %s -Encoding byte)) | set-content -path C:\\windows\\temp\\%s.txt -force | Out-Null"""%(resultTXT,keyName)
        command = self.__shell + self.encodeCommand(data)
        self.__win32Process.Create(command, self.__pwd, None)
        self.logger.info("Waiting {}s for command completely executed.".format(self.interval_time))
        time.sleep(self.interval_time)
        
        # Add base64 strings to registry
        registry_Path = "HKLM:\\Software\\Classes\\hello\\"
        self.logger.info("Adding base64 strings to registry, path: %s, keyname: %s"%(registry_Path,keyName))
        data = """New-Item %s -Force; New-ItemProperty -Path %s -Name %s -Value (get-content -path C:\\windows\\temp\\%s.txt) -PropertyType string -Force | Out-Null"""%(registry_Path,registry_Path,keyName,keyName)
        command = self.__shell + self.encodeCommand(data)
        self.__win32Process.Create(command, self.__pwd, None)
        self.logger.info("Waiting {}s for command completely executed.".format(self.interval_time))
        time.sleep(self.interval_time)
        
        # Remove temp file
        self.logger.info("Remove temporary files")
        data = ("del /q /f /s C:\\windows\\temp\\*")
        command = self.__shell + data
        self.__win32Process.Create(command, self.__pwd, None)

        # Get command results
        self.queryRegistry(keyName)

    def queryRegistry(self, keyName):
        #namespace = '//%s/root/default' % self.address
        try:
            descriptor, _ = self.iWbemServices.GetObject('StdRegProv')
            descriptor = descriptor.SpawnInstance()
            retVal = descriptor.GetStringValue(2147483650,'SOFTWARE\\classes\\hello', keyName)
            self.logger.success(f"Executed command: {self.command}")
            result = base64.b64decode(retVal.sValue).decode('utf-16le').rstrip('\r\n')
            self.logger.highlight(result)
        except:
            self.logger.fail("Execute command failed, probabaly got detection by AV.")
            descriptor.RemRelease()
            self.iWbemServices.RemRelease()
        else:
            self.logger.info("Remove temporary registry Key")
            retVal = descriptor.DeleteKey(2147483650,'SOFTWARE\\classes\\hello')
            descriptor.RemRelease()
            self.iWbemServices.RemRelease()
