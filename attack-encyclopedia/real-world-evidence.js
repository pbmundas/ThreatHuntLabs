"use strict";

(() => {
  const logs = {
    iisWebProbe: {
      source: "Microsoft IIS 10.0 — W3C access log",
      context: "A single source probes common administrative and secret-file paths, then submits a suspicious login request. Preserve the #Fields header because it defines every positional value below it.",
      raw: String.raw`#Software: Microsoft Internet Information Services 10.0
#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-substatus time-taken cs(User-Agent)
2026-08-08 03:12:41 198.51.100.77 GET /login.aspx - 200 0 118 Mozilla/5.0
2026-08-08 03:12:42 198.51.100.77 GET /admin/config.php - 404 0 12 python-requests/2.31.0
2026-08-08 03:12:42 198.51.100.77 GET /.env - 404 0 9 python-requests/2.31.0
2026-08-08 03:12:43 198.51.100.77 GET /wp-login.php - 404 0 11 python-requests/2.31.0
2026-08-08 03:12:43 198.51.100.77 GET /backup.sql - 404 0 10 python-requests/2.31.0
2026-08-08 03:12:44 198.51.100.77 POST /login.aspx username=admin'--&password=x 500 0 340 python-requests/2.31.0`,
      pivots: ["c-ip=198.51.100.77", "cs-method=POST", "cs-uri-stem=/login.aspx", "sc-status=500", "User-Agent=python-requests/2.31.0"],
      correlate: "Group by c-ip and a short time window; review the ordered URI sequence, application errors, WAF events, authentication results, and any server-side process or file activity."
    },
    fortiProxyC2: {
      source: "FortiProxy — forward proxy traffic",
      context: "Repeated GET/POST check-ins from one internal host to the same rare domain and destination can reveal command-and-control beaconing.",
      raw: String.raw`1754622930.412    287 10.10.4.55 TCP_MISS/200 154892 GET
http://cdn-analytics-update[.]com/api/v2/beacon -
HIER_DIRECT/104.21.44.19
application/octet-stream "Mozilla/5.0 (Windows NT 10.0; Win64; x64)
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0
Safari/537.36"

1754622991.087     94 10.10.4.55 TCP_MISS/200 892 POST
http://cdn-analytics-update[.]com/api/v2/checkin -
HIER_DIRECT/104.21.44.19
text/plain "Mozilla/5.0 (Windows NT 10.0; Win64; x64)
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0
Safari/537.36"

1754623051.203     88 10.10.4.55 TCP_MISS/200 891 POST
http://cdn-analytics-update[.]com/api/v2/checkin -
HIER_DIRECT/104.21.44.19
text/plain "Mozilla/5.0 (Windows NT 10.0; Win64; x64)
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0
Safari/537.36"`,
      pivots: ["client=10.10.4.55", "domain=cdn-analytics-update[.]com", "paths=/beacon,/checkin", "status=TCP_MISS/200", "interval≈60s"],
      correlate: "Calculate inter-arrival time and byte-size regularity, then pivot to DNS, endpoint process/network telemetry, TLS metadata, domain age, and other hosts contacting the destination."
    },
    fortiTrafficSsh: {
      source: "FortiGate — traffic log",
      context: "The firewall permits an inbound SSH session through DNAT. The accepted action is important when correlated with the preceding IPS brute-force alert.",
      raw: String.raw`date=2026-08-08 time=03:41:53 devname="FGT-EDGE-01"
devid="FG100F1234567890"
logid="0000000013" type="traffic" subtype="forward" level="notice"
srcip=45.155.205.88 srcport=44201 srcintf="wan1"
dstip=203.0.113.22 dstport=22 dstintf="internal"
poluuid="a1b2c3d4-1234-5678-90ab-cdef01234567" sessionid=8812234
proto=6 action="accept" policyid=8 policytype="policy"
service="SSH" dstcountry="United States" srccountry="Russian Federation"
trandisp="dnat" transip=10.10.1.10 transport=22
duration=3 sentbyte=412 rcvdbyte=298 sentpkt=6 rcvdpkt=5 crscore=30
crlevel="high"`,
      pivots: ["srcip=45.155.205.88", "dstport=22", "action=accept", "trandisp=dnat", "transip=10.10.1.10", "policyid=8"],
      correlate: "Join on srcip, destination, policyid, and ±2 seconds with FortiGate IPS, Linux sshd authentication, and endpoint session/process events."
    },
    fortiIpsSshBruteForce: {
      source: "FortiGate IPS — SSH brute-force alert",
      context: "The IPS identifies repeated SSH login attempts and records the count, source, destination, action, policy, and attack signature.",
      raw: String.raw`date=2026-08-08 time=03:41:52 devname="FGT-EDGE-01"
devid="FG100F1234567890"
eventtime=1754624512 logid="0419016384" type="utm" subtype="ips"
level="warning" vd="root" severity="medium" srcip=45.155.205.88
srcport=44192 srccountry="Russian Federation" dstip=203.0.113.22
dstport=22
dstintf="wan1" action="pass" attack="SSH.Brute.Force.Login"
attackid=44811 proto=6 policyid=8 msg="applications3:
SSH.Brute.Force.Login"
count=142`,
      pivots: ["attack=SSH.Brute.Force.Login", "count=142", "srcip=45.155.205.88", "dstport=22", "action=pass", "policyid=8"],
      correlate: "The alert is more urgent because action=pass. Look immediately for a successful/accepted SSH session from the same source and validate the target host's authentication logs."
    },
    fortiIpsLog4j: {
      source: "FortiGate IPS — Log4j exploitation alert",
      context: "A critical IPS signature records an attempted Log4j remote-code-execution path and the enforcement result.",
      raw: String.raw`date=2026-08-08 time=03:14:07 devname="FGT-EDGE-01"
devid="FG100F1234567890"
eventtime=1754622847 logid="0419016384" type="utm" subtype="ips"
level="alert" vd="root" severity="critical" srcip=185.220.101.47
srcport=53211 srccountry="Netherlands" dstip=203.0.113.15
dstport=443
dstintf="wan1" action="dropped"
attack="Apache.Log4j.Error.Log.Remote.Code.Execution"
attackid=53236
ref="https://www.fortiguard.com/encyclopedia/ips/53236"
profile="default" proto=6 policyid=12 msg="applications3:
Apache.Log4j.Error.Log.Remote.Code.Execution"`,
      pivots: ["severity=critical", "attackid=53236", "srcip=185.220.101.47", "dstport=443", "action=dropped", "policyid=12"],
      correlate: "A dropped perimeter event lowers—not removes—risk. Check reverse-proxy/application logs and endpoint telemetry for matching requests, child processes, outbound callbacks, or earlier permitted attempts."
    },
    windows5140Share: {
      source: "Windows Security — Event 5140",
      context: "A network share was accessed from a workstation using a service account. This provides share-level context but not the exact file operation.",
      raw: String.raw`Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      5140
Level:         Information
Computer:      DC01.corp.local
Description:   A network share object was accessed.
               Subject:
                   Account Name:  svc_backup
                   Account Domain: CORP
               Network Information:
                   Object Type:   File
                   Source Address: 10.10.4.55
                   Source Port:    51030
               Share Information:
                   Share Name:     \\*\C$
                   Share Path:     ${"C:\\"}`,
      pivots: ["EventID=5140", "AccountName=svc_backup", "SourceAddress=10.10.4.55", "ShareName=\\*\C$", "Computer=DC01.corp.local"],
      correlate: "Use Event 5145 for the relative target and access mask, then join to logon, process, service, and endpoint network telemetry."
    },
    sysmonService7045: {
      source: "Sysmon Event 1 + System Event 7045",
      context: "A service-host process launch and service-installation event form a stronger state-change sequence than either record alone.",
      raw: String.raw`Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      1
Description:   Process Create
               UtcTime: 2026-08-08 03:28:41.335
               Image: C:\Windows\System32\svchost.exe
               CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s SysUpdateSvc
               ParentImage: C:\Windows\System32\services.exe
               User: NT AUTHORITY\SYSTEM
               IntegrityLevel: System

Log Name:      System
Source:        Service Control Manager
Event ID:      7045
Description:   A service was installed in the system.
               Service Name:  SysUpdateSvc
               Service File Name: C:\Windows\Temp\update_svc.exe -k
               Service Type:  user mode service
               Service Start Type: auto start
               Service Account: LocalSystem`,
      pivots: ["EventID=7045", "ServiceName=SysUpdateSvc", "ServiceFile=C:\\Windows\\Temp\\update_svc.exe", "ParentImage=services.exe", "User=SYSTEM"],
      correlate: "Confirm file creation and signer/hash reputation for update_svc.exe, identify the process that created the service, and look for the first service start and outbound connection."
    },
    sysmonDumpSecrets: {
      source: "Sysmon — Event 1 (credential-dump process)",
      context: "A high-integrity process launches a suspicious credential-dumping command from a temporary directory.",
      raw: String.raw`Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      1
Description:   Process Create
               UtcTime: 2026-08-08 03:26:58.774
               Image: C:\Windows\Temp\update_svc.exe
               CommandLine: update_svc.exe --dump-secrets --target LOCAL
               ParentImage: C:\Windows\System32\cmd.exe
               User: CORP\jsmith
               IntegrityLevel: High`,
      pivots: ["Image=C:\\Windows\\Temp\\update_svc.exe", "CommandLine=--dump-secrets", "User=CORP\\jsmith", "IntegrityLevel=High", "ParentImage=cmd.exe"],
      correlate: "Pivot by ProcessGuid/process ID to Event 10 process access, Event 11 dump-file creation, the executable hash, and the account's preceding elevation or remote-access event."
    },
    security4657Registry: {
      source: "Windows Security — Event 4657",
      context: "This is a registry value modification in the LSA Secrets area. It is a useful native-format negative control: it is suspicious, but it is not a Run/RunOnce key and must not be mislabeled as Run-key persistence.",
      raw: String.raw`Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4657
Level:         Information
Computer:      FIN-WKS-014.corp.local
Description:   A registry value was modified.
               Subject:
                   Account Name:   jsmith
                   Account Domain: CORP
               Object:
                   Object Name: \\REGISTRY\\MACHINE\\SECURITY\\Policy\\Secrets
                   Object Value Name: DefaultPassword
               Process Information:
                   Process Name: C:\Windows\Temp\update_svc.exe`,
      pivots: ["EventID=4657", "ObjectName=...\\SECURITY\\Policy\\Secrets", "ValueName=DefaultPassword", "ProcessName=update_svc.exe", "AccountName=jsmith"],
      correlate: "Validate the exact registry path before mapping a technique. For Run-key persistence, require Run/RunOnce or another approved autorun path; here, investigate secret access and the responsible process instead."
    },
    sysmonDumpFile: {
      source: "Sysmon — Event 11 (dump file creation)",
      context: "The suspected dumping process creates an LSASS-named dump file, providing a concrete output artifact.",
      raw: String.raw`Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      11
Description:   File created
               UtcTime: 2026-08-08 03:25:19.401
               Image: C:\Windows\Temp\update_svc.exe
               TargetFilename: C:\Windows\Temp\lsass_dump_08082026.dmp
               CreationUtcTime: 2026-08-08 03:25:19.401`,
      pivots: ["EventID=11", "Image=update_svc.exe", "TargetFilename=*lsass*.dmp", "Directory=C:\\Windows\\Temp", "UtcTime=03:25:19.401"],
      correlate: "Link the creating process to LSASS process access, process creation, file hash, subsequent archive/staging activity, and any cleanup attempt."
    },
    security4656Lsass: {
      source: "Windows Security — Event 4656 (LSASS handle request)",
      context: "A non-standard binary requests memory-read and query access to lsass.exe. This is behaviorally closer to credential dumping than a generic failed logon.",
      raw: String.raw`Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4656
Level:         Information
Computer:      FIN-WKS-014.corp.local
Description:   A handle to an object was requested.
               Subject:
                   Account Name:   jsmith
                   Account Domain: CORP
               Object:
                   Object Server:  Security
                   Object Type:    Process
                   Object Name:    C:\Windows\System32\lsass.exe
                   Handle ID:      0x1410
               Process Information:
                   Process ID:     0x1E20
                   Process Name:   C:\Windows\Temp\update_svc.exe
               Access Request Information:
                   Accesses:       PROCESS_VM_READ,
                                   PROCESS_QUERY_INFORMATION`,
      pivots: ["EventID=4656", "ObjectName=lsass.exe", "Accesses=PROCESS_VM_READ", "ProcessName=update_svc.exe", "ProcessID=0x1E20"],
      correlate: "Resolve process ID 0x1E20 to process creation and hash data, then look for dump-file creation and any subsequent compression, transfer, or deletion."
    },
    sysmonPsexecNetwork: {
      source: "Sysmon — Event 1 + Event 3 (PsExec sequence)",
      context: "The service binary appears on the workstation while a service process connects to the domain controller over SMB.",
      raw: String.raw`Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      1
Description:   Process Create
               UtcTime: 2026-08-08 03:22:41.550
               Image: C:\Windows\PSEXESVC.exe
               CommandLine: C:\Windows\PSEXESVC.exe
               ParentImage: C:\Windows\System32\services.exe
               User: NT AUTHORITY\SYSTEM

Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      3
Description:   Network Connection
               UtcTime: 2026-08-08 03:22:38.910
               Image: C:\Windows\System32\services.exe
               Protocol: tcp
               SourceIp: 10.10.4.55
               SourceHostname: FIN-WKS-014.corp.local
               DestinationIp: 10.10.1.10
               DestinationHostname: DC01.corp.local
               DestinationPort: 445`,
      pivots: ["Image=PSEXESVC.exe", "ParentImage=services.exe", "User=SYSTEM", "DestinationPort=445", "SourceHost=FIN-WKS-014"],
      correlate: "Correlate with Security 5145 for the ADMIN$ write, System 7045 for service creation, logon events, and the initiating administrator or remote process."
    },
    security5145Psexec: {
      source: "Windows Security — Event 5145 (ADMIN$ write)",
      context: "The detailed share event records a request to write PSEXESVC.exe into the Windows administrative share.",
      raw: String.raw`Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      5145
Level:         Information
Computer:      DC01.corp.local
Description:   A network share object was checked to see whether client can be granted desired access.
               Subject:
                   Account Name:   svc_backup
                   Account Domain: CORP
               Network Information:
                   Object Type:    File
                   Source Address: 10.10.4.55
                   Source Port:    51022
               Share Information:
                   Share Name:     \\*\ADMIN$
                   Share Path:     C:\Windows
                   Relative Target Name: PSEXESVC.exe
               Access Request Information:
                   Access Mask:    0x2
                   Accesses:       WriteData (or AddFile)`,
      pivots: ["EventID=5145", "ShareName=\\*\\ADMIN$", "RelativeTarget=PSEXESVC.exe", "AccessMask=0x2", "SourceAddress=10.10.4.55"],
      correlate: "A write to ADMIN$ is not automatically malicious. Raise confidence when it is followed by Event 7045, PSEXESVC execution as SYSTEM, and unusual remote-administration context."
    },
    system7045Psexec: {
      source: "Windows System — Event 7045 (PSEXESVC)",
      context: "Service Control Manager confirms installation of the PsExec service binary as LocalSystem.",
      raw: String.raw`Log Name:      System
Source:        Service Control Manager
Event ID:      7045
Level:         Information
Computer:      DC01.corp.local
Description:   A service was installed in the system.
               Service Name:  PSEXESVC
               Service File Name: C:\Windows\PSEXESVC.exe
               Service Type:  user mode service
               Service Start Type: demand start
               Service Account: LocalSystem`,
      pivots: ["EventID=7045", "ServiceName=PSEXESVC", "ServiceFile=C:\\Windows\\PSEXESVC.exe", "StartType=demand", "Account=LocalSystem"],
      correlate: "Look backward for ADMIN$ file writes and network logons, then forward for service execution, child processes, target commands, and service/file cleanup."
    },
    sysmonPowerShell: {
      source: "Sysmon — Event 1 (encoded PowerShell)",
      context: "A high-integrity cmd.exe launches hidden, non-interactive, encoded PowerShell after local discovery commands.",
      raw: String.raw`Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      1
Description:   Process Create
               UtcTime: 2026-08-08 03:17:05.104
               Image: C:\Windows\System32\cmd.exe
               CommandLine: cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
               ParentImage: C:\Windows\System32\cmd.exe
               ParentCommandLine: cmd.exe /c whoami /all & net user & ipconfig /all
               User: CORP\jsmith
               IntegrityLevel: High
               Hashes: SHA256=B4D6A5F1C3E29A0D7F8B1234567890ABCDEF1234567890ABCDEF1234567890`,
      pivots: ["CommandLine=-nop -w hidden -enc", "ParentCommandLine=whoami/net user/ipconfig", "User=CORP\\jsmith", "IntegrityLevel=High", "SHA256=B4D6..."],
      correlate: "Decode the Base64 safely, reconstruct the parent/grandparent tree, and join PowerShell 4104/4103, AMSI/EDR, DNS, and network events by host and time."
    },
    security4688Cmd: {
      source: "Windows Security — Event 4688",
      context: "Native Windows process auditing records the command line, creator process, identity, and token elevation for the discovery command.",
      raw: String.raw`Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4688
Level:         Information
User:          CORP\jsmith
Computer:      FIN-WKS-014.corp.local
Description:   A new process has been created.
               Subject:
                   Security ID:        CORP\jsmith
                   Account Name:       jsmith
                   Account Domain:     CORP
                   Logon ID:           0x8B4F12
               Process Information:
                   New Process ID:     0x1AF0
                   New Process Name:   C:\Windows\System32\cmd.exe
                   Token Elevation Type: %%1936
                   Creator Process ID: 0x0C44
                   Creator Process Name: C:\Windows\explorer.exe
                   Process Command Line: cmd.exe /c whoami /all & net user & ipconfig /all`,
      pivots: ["EventID=4688", "NewProcess=cmd.exe", "CommandLine=whoami/net user/ipconfig", "CreatorProcess=explorer.exe", "LogonID=0x8B4F12"],
      correlate: "Join the logon ID and creator PID to authentication/session context, then follow child processes such as PowerShell and any resulting network connection."
    },
    sysmonWevtutil: {
      source: "Sysmon — Event 1 (wevtutil log clearing)",
      context: "The process command line explicitly clears Security, System, and Application logs under a service account.",
      raw: String.raw`Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      1
Description:   Process Create
               UtcTime: 2026-08-08 03:14:22.881
               ProcessGuid: {4a1e9c3f-2b17-6689-1500-000000001e00}
               ProcessId: 6820
               Image: C:\Windows\System32\wevtutil.exe
               CommandLine: wevtutil.exe cl Security
               CurrentDirectory: C:\Windows\System32\
               User: CORP\svc_backup
               LogonGuid: {4a1e9c3f-2b16-6689-c721-3e0000000000}
               LogonId: 0x3E7A21C
               ParentImage: C:\Windows\System32\cmd.exe
               ParentCommandLine: cmd.exe /c wevtutil.exe cl Security & wevtutil.exe cl System & wevtutil.exe cl Application`,
      pivots: ["Image=wevtutil.exe", "CommandLine=cl Security", "User=CORP\\svc_backup", "LogonId=0x3E7A21C", "ParentImage=cmd.exe"],
      correlate: "Alert on the process behavior, then verify the state change with Security 1102 and System 104. Preserve off-host copies because local evidence may be removed."
    },
    windowsLogCleared: {
      source: "Windows Security 1102 + System 104",
      context: "The operating system confirms both audit-log and System-log clearing, providing outcome evidence for the earlier wevtutil process.",
      raw: String.raw`Log Name:      Security
Source:        Microsoft-Windows-Eventlog
Event ID:      1102
Level:         Information
User:          CORP\svc_backup
Computer:      WEB-PROD-03.corp.local
Description:   The audit log was cleared.
               Subject:
                   Security ID:   CORP\svc_backup
                   Account Name:  svc_backup
                   Domain Name:   CORP
                   Logon ID:      0x3E7A21C

Log Name:      System
Source:        Microsoft-Windows-Eventlog
Event ID:      104
Level:         Information
User:          CORP\svc_backup
Computer:      WEB-PROD-03.corp.local
Description:   The System log file was cleared.
               Backup Path:
               Archive Attempts: 0`,
      pivots: ["EventID=1102", "EventID=104", "User=CORP\\svc_backup", "Computer=WEB-PROD-03", "LogonID=0x3E7A21C"],
      correlate: "Join by computer, user, logon ID, and time to process creation and remote-access events. Investigate why a service account could clear logs and whether Application was also cleared."
    },
    defenderEdrPowerShell: {
      source: "EDR alert — JSON evidence record",
      context: "The alert keeps its nested evidence structure, including process, parent process, identity, device, command line, and hash.",
      raw: String.raw`{
  "alertId": "da637d8f2b1e4a6f9c0d3e5f7a8b9c1d",
  "title": "Suspicious PowerShell command line",
  "severity": "High",
  "category": "CredentialAccess",
  "status": "New",
  "classification": "TruePositive",
  "determination": "MaliciousActivity",
  "detectionSource": "EDR",
  "machineId": "a1b2c3d4e5f6789012345678901234ab",
  "computerDnsName": "FIN-WKS-014.corp.local",
  "createdDateTime": "2026-08-08T03:17:06.104Z",
  "evidence": [
    {
      "entityType": "Process",
      "processId": 6820,
      "fileName": "powershell.exe",
      "processCommandLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
      "parentProcessFileName": "cmd.exe",
      "parentProcessCommandLine": "cmd.exe /c whoami /all & net user & ipconfig /all",
      "accountName": "jsmith",
      "sha256": "b4d6a5f1c3e29a0d7f8b1234567890abcdef1234567890abcdef1234567890"
    }
  ],
  "recommendedActions": "Isolate device, collect investigation package, review parent process tree"
}`,
      pivots: ["severity=High", "determination=MaliciousActivity", "machine=FIN-WKS-014", "processId=6820", "fileName=powershell.exe", "sha256=b4d6..."],
      correlate: "Use the device ID, process ID, timestamp, account, and hash to pivot into raw endpoint events. Treat the alert as a lead, not a replacement for source telemetry."
    }
  };

  const evidencePacks = {
    "powershell-abuse": {
      summary: "Follow the same execution from Windows process telemetry into the EDR alert without flattening away parent/child context.",
      logIds: ["security4688Cmd", "sysmonPowerShell", "defenderEdrPowerShell"]
    },
    "living-off-the-land": {
      summary: "Legitimate Windows utilities become suspicious through command-line intent, ancestry, identity, and the state change that follows.",
      logIds: ["security4688Cmd", "sysmonPowerShell", "sysmonWevtutil"]
    },
    "clear-windows-event-logs": {
      summary: "Correlate the clearing command with operating-system confirmation events; neither side alone tells the full story.",
      logIds: ["sysmonWevtutil", "windowsLogCleared"]
    },
    "security-tool-tampering": {
      summary: "Log clearing is a concrete defense-evasion state change that should be confirmed through both process and Event Log telemetry.",
      logIds: ["sysmonWevtutil", "windowsLogCleared"]
    },
    "lsass-credential-dumping": {
      summary: "Reconstruct the credential-dumping chain from LSASS access to suspicious execution and the dump artifact.",
      logIds: ["security4656Lsass", "sysmonDumpSecrets", "sysmonDumpFile"]
    },
    "windows-service-execution": {
      summary: "Service installation becomes high-confidence when the binary, account, start mode, process ancestry, and first execution agree.",
      logIds: ["sysmonService7045", "system7045Psexec"]
    },
    "remote-services": {
      summary: "The PsExec sequence crosses file-share, service-control, process, and network telemetry and should be hunted as one timeline.",
      logIds: ["security5145Psexec", "system7045Psexec", "sysmonPsexecNetwork", "windows5140Share"]
    },
    "ingress-tool-transfer": {
      summary: "An ADMIN$ write of PSEXESVC.exe demonstrates how transferred tooling can be confirmed at both the share and service layers.",
      logIds: ["security5145Psexec", "system7045Psexec"]
    },
    "brute-force": {
      summary: "Read the IPS alert and permitted firewall session together to determine whether repeated attempts may have progressed to access.",
      logIds: ["fortiIpsSshBruteForce", "fortiTrafficSsh"]
    },
    "password-guessing": {
      summary: "The activity targets one exposed SSH service repeatedly, so the source/destination count and subsequent accepted session matter more than a tool name.",
      logIds: ["fortiIpsSshBruteForce", "fortiTrafficSsh"]
    },
    "exploitation-of-public-facing-application": {
      summary: "Combine perimeter prevention with application-native access logs to determine whether exploitation was blocked, retried, or followed by server-side effects.",
      logIds: ["fortiIpsLog4j", "iisWebProbe"]
    },
    "sql-injection": {
      summary: "The IIS sequence preserves positional W3C fields and shows reconnaissance immediately before a malformed login request and server error.",
      logIds: ["iisWebProbe"]
    },
    "proxy-and-multi-hop-c2": {
      summary: "Proxy telemetry exposes periodic check-ins, stable destinations, request methods, paths, byte counts, and user-agent reuse.",
      logIds: ["fortiProxyC2"]
    },
    "registry-run-key-persistence": {
      summary: "Use this native 4657 record as a negative control: always validate the exact path before labeling a registry modification as Run-key persistence.",
      logIds: ["security4657Registry"]
    }
  };

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function buildLogSample(log, index) {
    const sample = element("div", "log-sample production-log-sample");
    const head = element("div", "log-sample-head");
    const source = element("div");
    source.append(element("span", "", `ORIGINAL SOURCE FORMAT · ${String(index + 1).padStart(2, "0")}`));
    source.append(element("strong", "", log.source));
    const copy = element("button", "copy-button", "COPY LOG");
    copy.type = "button";
    copy.setAttribute("data-copy-query", "");
    head.append(source, copy);

    const context = element("p", "", log.context);
    const pre = element("pre");
    pre.append(element("code", "", log.raw));

    const guide = element("div", "log-interpretation production-log-guide");
    guide.append(element("strong", "", "DETECTION PIVOTS — START HERE"));
    const pivots = element("ul", "production-pivots");
    log.pivots.forEach((pivot) => pivots.append(element("li", "", pivot)));
    guide.append(pivots);
    const correlate = element("p");
    correlate.append(element("b", "", "CORRELATE NEXT: "));
    correlate.append(document.createTextNode(log.correlate));
    guide.append(correlate);

    sample.append(head, context, pre, guide);
    return sample;
  }

  function renderEvidencePack() {
    const slug = window.location.pathname.split("/").pop().replace(/\.html$/, "");
    const pack = evidencePacks[slug];
    const section = document.querySelector("#log-examples > div:last-child");
    if (!pack || !section) return;

    const title = section.querySelector(":scope > h2");
    if (title) title.textContent = "Production-shaped log examples";
    const navLabel = document.querySelector('.study-nav a[href="#log-examples"]');
    if (navLabel) {
      const number = navLabel.querySelector("b")?.outerHTML || "";
      navLabel.innerHTML = `${number}Production-shaped logs`;
    }

    const wrapper = element("div", "production-evidence-pack");
    const intro = element("div", "production-evidence-intro");
    intro.append(element("span", "", "LAB EVIDENCE PACK · ORIGINAL EVENT SHAPE"));
    intro.append(element("strong", "", "Learn the fields as the source system emits them."));
    intro.append(element("p", "", `${pack.summary} These supplied training records retain their native multiline layout and field names. Use them to learn extraction and correlation—not as universal signatures or standalone proof.`));
    wrapper.append(intro);

    const stack = element("div", "log-sample-stack production-log-stack");
    pack.logIds.forEach((logId, index) => stack.append(buildLogSample(logs[logId], index)));
    wrapper.append(stack);

    const existingStack = section.querySelector(":scope > .log-sample-stack");
    const warning = section.querySelector(":scope > .evidence-warning");
    if (warning) {
      warning.querySelector("strong").textContent = "SCHEMA-SHAPED COMPANION EXAMPLES";
      warning.querySelector("p").textContent = "The examples after the evidence pack remain sanitized learning records. Compare their normalized fields with the original source formats above before adapting a production parser or detection.";
    }
    section.insertBefore(wrapper, warning || existingStack);
  }

  renderEvidencePack();
})();
