from collections import OrderedDict

menu_main = OrderedDict([
    ('General', 'menu_general'),
    ('Persistence','menu_persistence'),
    ('Credential Access','menu_creds'),
    ('Powershell','menu_powershell'),
    ('Emotet','menu_emotet'),
    ('LOLBINS','menu_lolbins'),
    ('Free search','free_search'),
    ('Toggle sweep mode (all instances or only the current)','toggle_sweep')
])

menu_general = OrderedDict([
    ('Back','back'),

    ('Autorun registry modifications', 
        '(regmod:software\microsoft\windows\currentversion\run\*)'),

    ('DealPly regmods', 
        '(regmod:Software\Microsoft\Windows\CurrentVersion\Run\GoogleChromeAutoLaunch_*)'),

    ('DealPly Headless Chromium Autoruns', 
        '(cmdline:"Software\\Microsoft\\Windows\\CurrentVersion\\Run") AND (cmdline:"chromium")'),

    ('DealPly binary copies (noisy in some envs)', 
        'cmdline:copy AND cmdline:/b'),

    ('Scheduled tasks via XML',
        '(cmdline:"/create" AND cmdline:"/F" AND cmdline:"/tn") AND process_name:schtasks.exe'),

    ('T1193 & T1173 - Spearphishing Attachment - Excel and Word   (!!! 5 and 6 correlates a lot each other)',
         '((process_name:msbuild.exe OR process_name:installutil.exe OR process_name:wmic.exe OR process_name:cmd.exe OR process_name:wscript.exe OR process_name:cscript.exe OR process_name:powershell*.exe OR process_name:mshta.exe) AND (parent_name:excel.exe OR parent_name:winword.exe) AND (-cmdline:"svn export" OR -cmdline:".ftp" OR -cmdline:"edw_rep" OR -cmdline:"Order Engineering Schedule" OR -cmdline:"Compare_Deps-v2_1.vbs" OR -cmdline:"ARUNJOB.vbs" OR -cmdline:"excelkb.txt" OR -cmdline:"Send.bat" OR -cmdline:CHECK-LI-1420.bat -cmdline:Deployments -cmdline:systeemit -cmdline:asennus$ -cmdline:marketdb_update))'),

    ('T1175 - Component Object Model and Distributed COM - Excel  (!!! 5 and 6 correlates a lot each other)',
        '((process_name:excel.exe parent_name:svchost.exe) (childproc_name:cmd.exe OR childproc_name:rundll32.exe OR childproc_name:powershell.exe OR childproc_name:cscript.exe OR childproc_name:wcsript.exe))'),

    ('Comms to named pipes (!!! warning, leading wildcard on *\appdata\local\\temp\*.dll)',
         '((cmdline:"/c echo" AND cmdline:"\\.\pipe\") OR (filemod:*\appdata\local\temp\*.dll AND netconn_count:[1 TO *] AND -digsig_result:"Signed"))'),

    ('Potential SharpHound, conns to named pipes, !!! wildcards',
         '(filemod:*\pipe\WKSSVC AND filemod:*\pipe\LSARPC AND filemod:*\pipe\SAMR)'),

    ('More scheduled tasks',
        '(((process_name:schtasks.exe and cmdline:/create) or (process_name:at.exe) or (process_name:wmic.exe and (cmdline:job or cmdline:create))) AND -cmdline:ClickToRun*)'),

    ('Rundll32 execution', 
        '(process_name:rundll32.exe) AND ((cmdline:javascript* AND (cmdline:eval OR cmdline:wscript.shell OR cmdline:wscript)) OR (childproc_name:cmd.exe OR childproc_name:wscript.exe OR childproc_name:powershell.exe))'),


    ('CVE-2020-0674 jscript.dll', 
        '(process_name:iexplore.exe OR process_name:iexplorer.exe) AND modload:jscript9.dll AND (childproc_name:cmd.exe OR childproc_name:powershell.exe OR childproc_name:wmic.exe)'),

    ('Weird process names',
        'process_name:iexplorer.exe OR process_name:lsasss.exe OR process_name:scvhost.exe'),

])

menu_powershell = OrderedDict([
    ('Back','back'),
    ('Powershell remote IEX execution   https://attack.mitre.org/wiki/Technique/T1086', 
        'process_name:powershell.exe AND (cmdline:"https" OR cmdline:"http") AND (cmdline:"downloadstring" OR cmdline:iex) AND (cmdline:".ps1" OR cmdline:".bat" OR cmdline:".exe" OR cmdline:".cmd")'),

    ('Powershell downgrade to version 2', 
        'process_name:powershell.exe AND (cmdline:"-ve 2" OR cmdline:"-ver 2" OR cmdline:"-vers 2" OR cmdline:"-versi 2" OR cmdline:"-versio 2" OR cmdline:"-version 2")'),

    ('Powershell encoded b64 strings (frombase64string & iex) !!! mby develope a function to go through b64 variations to detect case obfuscation?', 
        'process_name:powershell.exe AND (cmdline:frombase64string OR cmdline:-e OR cmdline:-en OR cmdline:-enc OR cmdline:-enco OR cmdline:-encod OR cmdline:-encodi OR cmdline:-encodin OR cmdline:-encoding OR cmdline:-encodedcommand OR cmdline:-encodedcomman OR cmdline:-encodedcomma OR cmdline:-encodedcomm OR cmdline:-encodedcom OR cmdline:-encodedco OR cmdline:-encodedc) AND (cmdline:*ZnJvbWJhc2U2NHN0cm* OR cmdline:*RnJvbUJhc2U2NFN0c* OR cmdline:*JvbUJhc2U2NFN0c* OR cmdline:*SUVY* OR cmdline:*aUVY* OR cmdline:*SWVY* OR cmdline:*SWV4* OR cmdline:*aWV4* OR cmdline:*SUV4* OR cmdline:*aWVY* OR cmdline:*aUV4*)'),

    ('Powershell obfuscation & DOSfuscation',
        '(process_name:cmd.exe OR process_name:powershell.exe) AND (cmdline:% OR cmdline:^ OR cmdline:cmdline:COMSPEC)'),

    ('Powershell susp. parameters and netconns',
        'process_name:powershell.exe AND netconn_count:[1 TO *] AND (cmdline:"-Enc" OR cmdline:"hidden" OR cmdline:"iex" OR cmdline:"invoke-expression" OR cmdline:COMSPEC OR cmdline:"downloadstring" OR cmdline:"download" OR cmdline:"new-object" OR cmdline:"webclient") AND -cmdline:Scripts -cmdline:Citrix -cmdline:TeamViewer_AD_Connector -ipaddr:[169.254.0.0 TO 169.254.255.255]'),

    ('Powershell ext. outbound connections [1 TO *]',
        'process_name:powershell.exe AND netconn_count:[1 TO *] -ipaddr:[169.254.0.0 TO 169.254.255.255] -ipaddr:[192.168.0.0 TO 192.168.255.255] -ipaddr:[10.0.0.0 TO 10.255.255.255] -ipaddr:127.0.0.1 -ipv6addr:::1 -ipv6addr:[fe80::0:0:0:0 TO fe80::ffff:ffff:ffff:ffff]'),

    ('Powershell ext. outbound connections [50 TO *] includes 10.0.0.0/8',
        'process_name:powershell.exe AND netconn_count:[50 TO *] -ipaddr:[169.254.0.0 TO 169.254.255.255] -ipaddr:[192.168.0.0 TO 192.168.255.255] -ipaddr:127.0.0.1 -ipv6addr:::1 -ipv6addr:[fe80::0:0:0:0 TO fe80::ffff:ffff:ffff:ffff]'),

    ('Powershell beaconing - outbound conns [50 TO *]',
        'process_name:powershell.exe AND netconn_count:[50 TO *] -ipaddr:[169.254.0.0 TO 169.254.255.255] -ipaddr:[192.168.0.0 TO 192.168.255.255] -ipaddr:[10.0.0.0 TO 10.255.255.255] -ipaddr:127.0.0.1 -ipv6addr:::1 -ipv6addr:[fe80::0:0:0:0 TO fe80::ffff:ffff:ffff:ffff]'),

    ('Powershell w/ netconns and encoded or -exec or -bypass or -hidden (needs tuning)',
        'process_name:powershell.exe AND netconn_count:[1 TO *] AND (cmdline:-e* OR cmdline:”-Exec” OR cmdline:”bypass” OR cmdline:”hidden”)'),

    ('Run all','run_all'),
])

menu_emotet = OrderedDict([
    ('Back','back'),
    ('cmd shells spawning from Microsoft Office products',
        '(parent_name:winword.exe OR parent_name:excel.exe OR parent_name:powerpnt.exe) AND (process_name:cmd.exe OR process_name:powershell.exe)'),

    ('WMI spawning powershell', 
        'parent_name:wmiprvse.exe AND process_name:powershell.exe AND cmdline:-e'),

    ('unsigned binaries making registry persistence (CurrentVersion\\Run)', 
        'regmod:Software\Microsoft\Windows\CurrentVersion\Run* AND digsig_result:Unsigned'),

    ('For the execution immediately following lateral movement via Windows Admin Shares, this hunt will be useful AFTER TUNING OUT driver or Windows components that are unsigned: "path:Windows\System32* OR path:Windows\SysWOW64*) AND digsig_result:Unsigned AND parent_name:services.exe"', 
        '(path:Windows\System32* OR path:Windows\SysWOW64*) AND digsig_result:Unsigned AND parent_name:services.exe'),

    ('Office product drops script in Appdata (including new .JSE)',
        '(process_name:winword.exe OR process_name:excel.exe) AND (filemod:*\appdata\roaming\*.jse OR filemod:*\appdata\roaming\*.vbs filemod:*\appdata\roaming\*.js OR filemod:*\appdata\roaming\*.bat OR filemod:*\appdata\roaming\*.bat OR filemod:*\appdata\roaming\*.url OR filemod:*\appdata\roaming\*.cmd OR filemod:*\appdata\roaming\*.hta OR filemod:*\appdata\roaming\*.ps1)'),
])

menu_creds = OrderedDict([
    ('Back','back'),
    ('ESENTUTL.EXE AD database dump (ntds.dit)',
        'process_name:esentutl.exe AND cmdline:"/vss"'),

    ('NTDSUTIL.EXE AD database dump',
        'process_name:ntdsutil.exe AND cmdline:"ac i ntds"'),

    ('reg.exe save - HKLM/SAM,SYSTEM,SECURITY dumps',
        'process_name:reg.exe AND (cmdline:save AND (cmdline:"HKLM\\SAM" OR cmdline:"HKLM\\SECURITY"))'),

    ('Mimikatz internal file signature detection',
        'company_name:"gentilkiwi (Benjamin DELPY)" OR internal_name:mimidrv'),

    ('Mimikatz typical modloads',
        '(modload:advapi32.dll AND modload:crypt32.dll AND modload:cryptdll.dll AND modload:gdi32.dll AND modload:imm32.dll AND modload:kernel32.dll AND modload:KernelBase.dll AND modload:msasn1.dll AND modload:msvcrt.dll AND modload:ntdll.dll AND modload:rpcrt4.dll AND modload:rsaenh.dll AND modload:samlib.dll AND modload:sechost.dll AND modload:secur32.dll AND modload:shell32.dll AND modload:shlwapi.dll AND modload:sspicli.dll AND modload:user32.dll)'),

    ('Unsigned binary loads samlib.dll and advapi.dll',
        'digsig_result:"Unsigned" modload:samlib.dll modload:advapi32.dll'),

    ('LSASS dump to .dmp',
        'filemod:lsass*.dmp'),

    ('Procdump usage',
        '(process_name:procdump.exe OR process_name:procdump.64.exe OR file_desc:"sysinternals process dump utility" OR product_name:"procdump")'),

    ('Secretsdump (DCSync)',
        'cmdline: dcsync OR cmdline:ZGNzeW4 OR cmdline:RGNzeW4 OR cmdline:ZENzeW4 OR cmdline:RENzeW4 OR cmdline:ZGNTeW4 OR cmdline:RGNTeW4 OR cmdline:ZENTeW4 OR cmdline:RENTeW4 OR cmdline:ZGNzWW4 OR cmdline:RGNzWW4 OR cmdline:ZENzWW4 OR cmdline:RENzWW4 OR cmdline:ZGNTWW4 OR cmdline:RGNTWW4 OR cmdline:ZENTWW4 OR cmdline:RENTWW4 OR cmdline:ZGNzeU4 OR cmdline:RGNzeU4 OR cmdline:ZENzeU4 OR cmdline:RENzeU4 OR cmdline:ZGNTeU4 OR cmdline:RGNTeU4 OR cmdline:ZENTeU4 OR cmdline:RENTeU4 OR cmdline:ZGNzWU4 OR cmdline:RGNzWU4 OR cmdline:ZENzWU4 OR cmdline:RENzWU4 OR cmdline:ZGNTWU4 OR cmdline:RGNTWU4 OR cmdline:ZENTWU4 OR cmdline:RENTWU4'),
])

menu_persistence = OrderedDict([
    ('Back','back'),
    ('Autorun registries', 
        'regmod:software\microsoft\windows\ nt\currentversion\winlogon\\userinit OR regmod:"software\microsoft\windows nt\currentversion\winlogon\shell" OR regmod:"Software\\Microsoft\\Windows\\CurrentVersion\\Run"'),

    ('unsigned binaries making registry persistence (CurrentVersion\\Run*)', 
        'regmod:Software\Microsoft\Windows\CurrentVersion\Run* AND digsig_result:Unsigned'),
    
])

menu_lolbins = OrderedDict([
    ('Back','back'),
    ('ESENTUTL.EXE AD database dump (ntds.dit)',
        'process_name:esentutl.exe AND cmdline:"/vss"'),

    ('NTDSUTIL.EXE AD database dump',
        'process_name:ntdsutil.exe'),

    ('certutil.exe downloads',
        'process_name:certutil.exe AND ((cmdline:"-urlcache" OR cmdline:"-verifyctl") AND cmdline:"-split")'),

    ('cmdkey.exe list cached credentials',
        'process_name:cmdkey.exe AND cmdline:"/list"'),

    ('hh.exe script DLs and process execs',
        'process_name:hh.exe AND ((cmdline:"http" AND (cmdline:"ps1" OR cmdline:"bat" OR cmdline:"cmd")) OR cmdline:"exe")'),

    ('rundll32 execution (can be noisy...)', 
        '(process_name:rundll32.exe) AND ((cmdline:javascript* AND (cmdline:eval OR cmdline:wscript.shell OR cmdline:wscript)) OR (childproc_name:cmd.exe OR childproc_name:wscript.exe OR childproc_name:powershell.exe))'),

    ('SQLToolsPS.exe process execs',
        'process_name:sqltoolsps.exe AND ((cmdline:"-c" OR cmdline:"-co" OR cmdline:"-com" OR cmdline:"-comm" OR cmdline:"-comma" OR cmdline:"-comman" OR cmdline:"-command") AND cmdline:"start-process")'),

    ('Clearing logs via WevtUtil.exe',
        'cmdline:"wevtutil.exe cl" AND (cmdline:security OR cmdline:application OR cmdline:system) AND -username:SYSTEM'),

    ('SettingSyncHost.exe -LoadAndRunDiagScript',
        'process_name:SettingSyncHost.exe AND cmdline:"-LoadAndRunDiagScript"'),

    ('wsreset.exe UAC-bypass - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/',
        'process_name:wsreset.exe'),

    ('wsreset - regmod:"HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command"',
        'regmod:Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command*')
])