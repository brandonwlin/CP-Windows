powershell.exe -noprofile -executionpolicy bypass -file "%~dp0\SvcMgmt.ps1"
#Bad Services
    cmd.exe /c 'sc stop tlntsvr'
    cmd.exe /c 'sc config tlntsvr start= disabled'
    cmd.exe /c 'sc stop Telephony'
    cmd.exe /c 'sc config Telephony start= disabled'
    cmd.exe /c 'sc stop ShellHWDetection'
    cmd.exe /c 'sc config ShellHWDetection start= disabled'
    cmd.exe /c 'sc stop WinHttpAutoProxySvc'
    cmd.exe /c 'sc config WinHttpAutoProxySvc start= disabled'
    cmd.exe /c 'sc stop SZCSVC'
    cmd.exe /c 'sc config SZCSVC start= disabled'
    cmd.exe /c 'sc stop msftpsvc'
    cmd.exe /c 'sc config msftpsvc start= disabled'
    cmd.exe /c 'sc stop snmptrap'
    cmd.exe /c 'sc config snmptrap start= disabled'
    cmd.exe /c 'sc stop ssdpsrv'
    cmd.exe /c 'sc config ssdpsrv start= disabled'
    cmd.exe /c 'sc stop termservice'
    cmd.exe /c 'sc config termservice start= disabled'
    cmd.exe /c 'sc stop sessionenv'
    cmd.exe /c 'sc config sessionenv start= disabled'
    cmd.exe /c 'sc stop remoteregistry'
    cmd.exe /c 'sc config remoteregistry start= disabled'
    cmd.exe /c 'sc stop Messenger'
    cmd.exe /c 'sc config Messenger start= disabled'
    cmd.exe /c 'sc stop upnphos'
    cmd.exe /c 'sc config upnphos start= disabled'
    cmd.exe /c 'sc stop WAS'
    cmd.exe /c 'sc config WAS start= disabled'
    #Remote Access/RDP
    #cmd.exe /c 'sc stop RemoteAccess'
    #cmd.exe /c 'sc config RemoteAccess start= disabled'
    cmd.exe /c 'sc stop mnmsrvc'
    cmd.exe /c 'sc config mnmsrvc start= disabled'
    cmd.exe /c 'sc stop NetTcpPortSharing'
    cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
    cmd.exe /c 'sc stop RasMan'
    cmd.exe /c 'sc config RasMan start= disabled'
    cmd.exe /c 'sc stop TabletInputService'
    cmd.exe /c 'sc config TabletInputService start= disabled'
    cmd.exe /c 'sc stop RpcSs'
    cmd.exe /c 'sc config RpcSs start= disabled'
    cmd.exe /c 'sc stop SENS'
    cmd.exe /c 'sc config SENS start= disabled'
    cmd.exe /c 'sc stop EventSystem'
    cmd.exe /c 'sc config EventSystem start= disabled'
    cmd.exe /c 'sc stop XblAuthManager'
    cmd.exe /c 'sc config XblAuthManager start= disabled'
    cmd.exe /c 'sc stop XblGameSave'
    cmd.exe /c 'sc config XblGameSave start= disabled'
    cmd.exe /c 'sc stop XboxGipSvc'
    cmd.exe /c 'sc config XboxGipSvc start= disabled'
    cmd.exe /c 'sc stop xboxgip'
    cmd.exe /c 'sc config xboxgip start= disabled'
    cmd.exe /c 'sc stop xbgm'
    cmd.exe /c 'sc config xbgm start= disabled'
    cmd.exe /c 'sc stop SysMain'
    cmd.exe /c 'sc config SysMain start= disabled'
    cmd.exe /c 'sc stop seclogon'
    cmd.exe /c 'sc config seclogon start= disabled'
    cmd.exe /c 'sc stop TapiSrv'
    cmd.exe /c 'sc config TapiSrv start= disabled'
    cmd.exe /c 'sc stop p2pimsvc'
    cmd.exe /c 'sc config p2pimsvc start= disabled'
    cmd.exe /c 'sc stop simptcp'
    cmd.exe /c 'sc config simptcp start= disabled'
    cmd.exe /c 'sc stop fax'
    cmd.exe /c 'sc config fax start= disabled'
    cmd.exe /c 'sc stop Msftpsvc'
    cmd.exe /c 'sc config Msftpsvc start= disabled'
    cmd.exe /c 'sc stop iprip'
    cmd.exe /c 'sc config iprip start= disabled'
    cmd.exe /c 'sc stop ftpsvc'
    cmd.exe /c 'sc config ftpsvc start= disabled'
    cmd.exe /c 'sc stop RasAuto'
    cmd.exe /c 'sc config RasAuto start= disabled'
    cmd.exe /c 'sc stop W3svc'
    cmd.exe /c 'sc config W3svc start= disabled'
    cmd.exe /c 'sc stop Smtpsvc'
    cmd.exe /c 'sc config Smtpsvc start= disabled'
    cmd.exe /c 'sc stop Dfs'
    cmd.exe /c 'sc config Dfs start= disabled'
    cmd.exe /c 'sc stop TrkWks'
    cmd.exe /c 'sc config TrkWks start= disabled'
    cmd.exe /c 'sc stop MSDTC'
    cmd.exe /c 'sc config MSDTC start= disabled'
    cmd.exe /c 'sc stop ERSvc'
    cmd.exe /c 'sc config ERSvc start= disabled'
    cmd.exe /c 'sc stop NtFrs'
    cmd.exe /c 'sc config NtFrs start= disabled'
    #IIS Stuff
    #cmd.exe /c 'sc stop Iisadmin'
    #cmd.exe /c 'sc config Iisadmin start= disabled'
    cmd.exe /c 'sc stop IsmServ'
    cmd.exe /c 'sc config IsmServ start= disabled'
    cmd.exe /c 'sc stop WmdmPmSN'
    cmd.exe /c 'sc config WmdmPmSN start= disabled'
    cmd.exe /c 'sc stop helpsvc'
    cmd.exe /c 'sc config helpsvc start= disabled'
    cmd.exe /c 'sc stop Spooler'
    cmd.exe /c 'sc config Spooler start= disabled'
    cmd.exe /c 'sc stop RDSessMgr'
    cmd.exe /c 'sc config RDSessMgr start= disabled'
    cmd.exe /c 'sc stop RSoPProv'
    cmd.exe /c 'sc config RSoPProv start= disabled'
    cmd.exe /c 'sc stop SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= disabled'
    cmd.exe /c 'sc stop lanmanserver'
    cmd.exe /c 'sc config lanmanserver start= disabled'
    cmd.exe /c 'sc stop Sacsvr'
    cmd.exe /c 'sc config Sacsvr start= disabled'
    cmd.exe /c 'sc stop TermService'
    cmd.exe /c 'sc config TermService start= disabled'
    cmd.exe /c 'sc stop uploadmgr'
    cmd.exe /c 'sc config uploadmgr start= disabled'
    cmd.exe /c 'sc stop VDS'
    cmd.exe /c 'sc config VDS start= disabled'
    cmd.exe /c 'sc stop VSS'
    cmd.exe /c 'sc config VSS start= disabled'
    cmd.exe /c 'sc stop WINS'
    cmd.exe /c 'sc config WINS start= disabled'
    cmd.exe /c 'sc stop CscService'
    cmd.exe /c 'sc config CscService start= disabled'
    cmd.exe /c 'sc stop hidserv'
    cmd.exe /c 'sc config hidserv start= disabled'
    cmd.exe /c 'sc stop IPBusEnum'
    cmd.exe /c 'sc config IPBusEnum start= disabled'
    cmd.exe /c 'sc stop PolicyAgent'
    cmd.exe /c 'sc config PolicyAgent start= disabled'
    cmd.exe /c 'sc stop SCPolicySvc'
    cmd.exe /c 'sc config SCPolicySvc start= disabled'
    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop SSDPSRV'
    cmd.exe /c 'sc config SSDPSRV start= disabled'
    cmd.exe /c 'sc stop Themes'
    cmd.exe /c 'sc config Themes start= disabled'
    cmd.exe /c 'sc stop upnphost'
    cmd.exe /c 'sc config upnphost start= disabled'
    cmd.exe /c 'sc stop nfssvc'
    cmd.exe /c 'sc config nfssvc start= disabled'
    cmd.exe /c 'sc stop nfsclnt'
    cmd.exe /c 'sc config nfsclnt start= disabled'
    #MSSQL
    #cmd.exe /c 'sc stop MSSQLServerADHelper'
    #cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'
    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop UmRdpService'
    cmd.exe /c 'sc config UmRdpService start= disabled'
    cmd.exe /c 'sc stop SessionEnv'
    cmd.exe /c 'sc config SessionEnv start= disabled'
    cmd.exe /c 'sc stop TeamViewer'
    cmd.exe /c 'sc config TeamViewer start= disabled'
    cmd.exe /c 'sc stop TeamViewer7'
    cmd.exe /c 'sc config start= disabled'
    cmd.exe /c 'sc stop HomeGroupListener'
    cmd.exe /c 'sc config HomeGroupListener start= disabled'
    cmd.exe /c 'sc stop HomeGroupProvider'
    cmd.exe /c 'sc config HomeGroupProvider start= disabled'
    cmd.exe /c 'sc stop AxInstSV'
    cmd.exe /c 'sc config AXInstSV start= disabled'
    cmd.exe /c 'sc stop Netlogon'
    cmd.exe /c 'sc config Netlogon start= disabled'
    cmd.exe /c 'sc stop lltdsvc'
    cmd.exe /c 'sc config lltdsvc start= disabled'
    cmd.exe /c 'sc stop iphlpsvc'
    cmd.exe /c 'sc config iphlpsvc start= disabled'
    cmd.exe /c 'sc stop AdobeARMservice'
    cmd.exe /c 'sc config AdobeARMservice start= disabled'
#Good Services
    cmd.exe /c 'sc start wuauserv'
    cmd.exe /c 'sc config wuauserv start= auto'
    cmd.exe /c 'sc start EventLog'
    cmd.exe /c 'sc config EventLog start= auto'
    cmd.exe /c 'sc start MpsSvc'
    cmd.exe /c 'sc config MpsSvc start= auto'
    cmd.exe /c 'sc start WinDefend'
    cmd.exe /c 'sc config WinDefend start= auto'
    cmd.exe /c 'sc start WdNisSvc'
    cmd.exe /c 'sc config WdNisSvc start= auto'
    cmd.exe /c 'sc start Sense'
    cmd.exe /c 'sc config Sense start= auto'
    cmd.exe /c 'sc start Schedule'
    cmd.exe /c 'sc config Schedule start= auto'
    cmd.exe /c 'sc start SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= auto'
    cmd.exe /c 'sc start ScDeviceEnum'
    cmd.exe /c 'sc config ScDeviceEnum start= auto'
    cmd.exe /c 'sc start SCPolicySvc'
    cmd.exe /c 'sc config SCPolicySvc start= auto'
    cmd.exe /c 'sc start wscsvc'
    cmd.exe /c 'sc config wscsvc start= auto'