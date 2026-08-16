"use strict";

(() => {
  const suppliedEvidenceSlugs = new Set([
    "powershell-abuse", "living-off-the-land", "clear-windows-event-logs",
    "security-tool-tampering", "lsass-credential-dumping", "windows-service-execution",
    "remote-services", "ingress-tool-transfer", "brute-force", "password-guessing",
    "exploitation-of-public-facing-application", "sql-injection",
    "proxy-and-multi-hop-c2", "registry-run-key-persistence"
  ]);

  const profiles = new Map();
  const register = (type, rows) => rows.forEach((row) => {
    const [slug, code, operation, fieldText] = row.split("|");
    const fields = Object.fromEntries(fieldText.split(";").map((entry) => {
      const split = entry.indexOf("=");
      return [entry.slice(0, split), entry.slice(split + 1)];
    }));
    profiles.set(slug, { type, code, operation, fields });
  });

  register("identity", [
    "account-manipulation|AuditLogs|Update user|actor=helpdesk.admin@corp.local;target=svc_backup@corp.local;property=accountEnabled;oldValue=false;newValue=true;sourceIp=10.10.4.21",
    "adversary-in-the-middle-phishing|SigninLogs|Interactive sign-in with replayed session|user=finance.director@corp.local;sourceIp=198.51.100.44;result=success;authenticationRequirement=multiFactorAuthentication;tokenBinding=none;sessionId=4f3b2a19",
    "application-access-token-theft|ServicePrincipalSignInLogs|Access token used without interactive sign-in|appId=1b730954-1685-4b74-9bfd-dac224a7b894;servicePrincipal=GraphSync;sourceIp=203.0.113.64;resource=Microsoft Graph;result=success;credentialType=clientSecret",
    "credential-stuffing|SigninLogs|Distributed password replay|sourceIp=198.51.100.77;targets=46;failures=44;successes=2;clientApp=Browser;userAgent=python-requests/2.31.0",
    "default-account-abuse|SigninLogs|Default account sign-in|user=admin@corp.local;sourceIp=203.0.113.91;result=success;deviceId=unknown;conditionalAccess=notApplied;firstSeen=true",
    "golden-saml|SigninLogs|Federated SAML token accepted|user=global.admin@corp.local;issuer=ADFS01.corp.local;tokenIssuerType=ADFederationServices;sourceIp=198.51.100.88;result=success;mfaClaim=true",
    "mfa-fatigue|AuthenticationEvents|Repeated push prompts followed by approval|user=jsmith@corp.local;sourceIp=185.220.101.55;pushes=12;denied=11;approved=1;elapsedSeconds=184",
    "mfa-interception|AuthenticationEvents|One-time code accepted from new context|user=ap.user@corp.local;challengeIp=10.10.4.55;redeemIp=203.0.113.82;factor=otp;elapsedSeconds=7;result=success",
    "oauth-consent-phishing|AuditLogs|Consent to application|actor=jsmith@corp.local;appDisplayName=Document Viewer Pro;appId=7a0d6e21;permissions=Mail.Read Files.Read.All offline_access;consentType=AllPrincipals;sourceIp=198.51.100.29",
    "password-reset-poisoning|AuditLogs|Reset password and modify recovery method|actor=helpdesk.agent@corp.local;target=cfo@corp.local;newMethod=+1-555-0109;sourceIp=203.0.113.71;result=success;ticketId=HD-88214",
    "password-spraying|SigninLogs|One password attempted across many users|sourceIp=198.51.100.48;distinctUsers=83;failures=82;successes=1;timeWindowMinutes=9;clientApp=Browser",
    "sim-swapping|CarrierAudit|Subscriber SIM changed|subscriber=+1-555-0148;oldIccid=89014103211118510720;newIccid=89014103211118510991;channel=call-center;agent=csr-1042;riskFlag=identity-verification-failed"
  ]);

  register("windows", [
    "as-rep-roasting|4768|Kerberos authentication ticket requested without pre-authentication|TargetUserName=svc_legacy;ServiceName=krbtgt;PreAuthType=0;TicketEncryptionType=0x17;IpAddress=10.10.4.55;Status=0x0",
    "cached-domain-credential-theft|4656|Credential cache registry object opened|SubjectUserName=jsmith;ObjectType=Key;ObjectName=\\REGISTRY\\MACHINE\\SECURITY\\Cache;ProcessName=C:\\Windows\\Temp\\credtool.exe;Accesses=ReadKey QueryValue;Computer=FIN-WKS-014",
    "dcshadow|5137|Rogue directory server object created|SubjectUserName=adm.ops;ObjectClass=nTDSDSA;ObjectDN=CN=NTDS Settings,CN=WIN-ADMIN,CN=Servers,CN=Default-First-Site-Name;OperationType=Object Access;Computer=DC01;SourceIp=10.10.4.55",
    "dcsync|4662|Directory replication right used|SubjectUserName=svc_backup;ObjectType=domainDNS;ObjectName=DC=corp,DC=local;Properties=Replicating Directory Changes All;AccessMask=0x100;Computer=DC01",
    "golden-ticket|4769|Anomalous Kerberos service ticket requested|TargetUserName=administrator;ServiceName=cifs/DC01.corp.local;TicketEncryptionType=0x17;TicketOptions=0x40810000;IpAddress=10.10.4.55;Status=0x0",
    "group-policy-preferences-credential-theft|4663|Group Policy Preferences file read|SubjectUserName=jsmith;ObjectName=\\DC01\\SYSVOL\\corp.local\\Policies\\{31B2F340}\\Machine\\Preferences\\Groups\\Groups.xml;Accesses=ReadData;ProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe;SourceIp=10.10.4.55",
    "kerberoasting|4769|Service ticket requested with RC4 encryption|TargetUserName=jsmith;ServiceName=MSSQLSvc/sql01.corp.local:1433;TicketEncryptionType=0x17;TicketOptions=0x40810000;IpAddress=10.10.4.55;Status=0x0",
    "kerberos-delegation-abuse|5136|Delegation attribute modified|SubjectUserName=adm.ops;ObjectDN=CN=WEB01,OU=Servers,DC=corp,DC=local;AttributeLDAPDisplayName=msDS-AllowedToActOnBehalfOfOtherIdentity;OperationType=Value Added;Computer=DC01",
    "ntds-dit-theft|4663|Active Directory database accessed|SubjectUserName=svc_backup;ObjectName=C:\\Windows\\NTDS\\ntds.dit;Accesses=ReadData;ProcessName=C:\\Windows\\System32\\esentutl.exe;HandleId=0x2f8;Computer=DC01",
    "pass-the-hash|4624|NTLM network logon without Kerberos|TargetUserName=administrator;LogonType=3;AuthenticationPackageName=NTLM;LmPackageName=NTLM V2;KeyLength=0;IpAddress=10.10.4.55",
    "pass-the-ticket|4769|Kerberos ticket replayed from a new host|TargetUserName=jsmith;ServiceName=cifs/FILE01.corp.local;TicketEncryptionType=0x12;IpAddress=10.10.4.99;WorkstationName=UNMANAGED-01;Status=0x0",
    "private-key-theft|4663|Machine private key file read|SubjectUserName=jsmith;ObjectName=C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\3f4a...;Accesses=ReadData;ProcessName=C:\\Windows\\Temp\\certgrab.exe;Computer=FIN-WKS-014",
    "shadow-credentials|5136|Key credential link added|SubjectUserName=adm.ops;ObjectDN=CN=WEB01,OU=Servers,DC=corp,DC=local;AttributeLDAPDisplayName=msDS-KeyCredentialLink;OperationType=Value Added;Computer=DC01",
    "silver-ticket|4769|Service ticket observed without expected TGT sequence|TargetUserName=svc_sql;ServiceName=MSSQLSvc/SQL01.corp.local:1433;TicketEncryptionType=0x17;IpAddress=10.10.4.55;Preceding4768=false;Status=0x0",
    "web-cookie-forgery|4624|Application identity accepted without preceding authentication|TargetUserName=web.admin;LogonType=8;AuthenticationPackageName=Negotiate;IpAddress=198.51.100.92;SessionCookieId=9f10a77c;PrecedingLogin=false"
  ]);

  register("sysmon", [
    "password-cracking|1|Offline password-cracking process launched|Image=C:\\Tools\\hashcat.exe;CommandLine=hashcat.exe -m 1000 hashes.txt wordlist.txt;ParentImage=C:\\Windows\\System32\\cmd.exe;User=CORP\\jsmith;IntegrityLevel=High;Hashes=SHA256=7A14...",
    "sam-database-dumping|1|SAM and SYSTEM hives exported|Image=C:\\Windows\\System32\\reg.exe;CommandLine=reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save;ParentImage=C:\\Windows\\System32\\cmd.exe;User=CORP\\jsmith;IntegrityLevel=High;Target=C:\\Windows\\Temp\\sam.save",
    "session-cookie-theft|11|Browser cookie database copied|Image=C:\\Windows\\Temp\\collector.exe;TargetFilename=C:\\Windows\\Temp\\Cookies.db;SourcePath=C:\\Users\\jsmith\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies;User=CORP\\jsmith;UtcTime=2026-08-08 03:25:19.401",
    "skeleton-key|10|Unauthorized process accessed LSASS for modification|SourceImage=C:\\Windows\\Temp\\authpatch.exe;TargetImage=C:\\Windows\\System32\\lsass.exe;GrantedAccess=0x1F0FFF;SourceUser=CORP\\adm.ops;CallTrace=ntdll.dll+kernelbase.dll;Computer=DC01",
    "token-impersonation|1|Process created under a duplicated privileged token|Image=C:\\Windows\\System32\\cmd.exe;CommandLine=cmd.exe /c whoami;ParentImage=C:\\Windows\\Temp\\token_tool.exe;User=NT AUTHORITY\\SYSTEM;IntegrityLevel=System;LogonId=0x3e7",
    "bootkit|6|Unsigned boot-start driver loaded|Image=C:\\Windows\\System32\\drivers\\bootflt.sys;SignatureStatus=Invalid;StartType=Boot;Hashes=SHA256=9C81...;Computer=FIN-WKS-014;User=NT AUTHORITY\\SYSTEM",
    "clipboard-hijacking|22|Process repeatedly read clipboard and replaced wallet text|Image=C:\\Users\\jsmith\\AppData\\Roaming\\clipmon.exe;ClipboardReadCount=48;ReplacementPattern=bc1q*;ParentImage=C:\\Windows\\explorer.exe;User=CORP\\jsmith;UtcTime=2026-08-08 03:22:41.550",
    "computer-worm|3|Same binary connected to many internal SMB hosts|Image=C:\\Windows\\Temp\\update.exe;DestinationPort=445;DistinctDestinationIp=147;SourceIp=10.10.4.55;User=NT AUTHORITY\\SYSTEM;TimeWindowSeconds=90",
    "data-staging-and-archiving|1|Archive utility staged collected data|Image=C:\\Program Files\\7-Zip\\7z.exe;CommandLine=7z.exe a C:\\ProgramData\\cache\\docs.7z C:\\Users\\*\\Documents\\*;ParentImage=C:\\Windows\\System32\\cmd.exe;User=CORP\\jsmith;Target=C:\\ProgramData\\cache\\docs.7z",
    "dll-search-order-hijacking|7|Unsigned DLL loaded before expected system library|ImageLoaded=C:\\Program Files\\Contoso\\version.dll;ProcessImage=C:\\Program Files\\Contoso\\Updater.exe;SignatureStatus=Unsigned;ExpectedPath=C:\\Windows\\System32\\version.dll;User=CORP\\jsmith;Hashes=SHA256=3A51...",
    "dll-side-loading|7|Trusted signed executable loaded adjacent unsigned DLL|ProcessImage=C:\\Users\\Public\\Teams.exe;ImageLoaded=C:\\Users\\Public\\version.dll;ProcessSignature=Microsoft;DllSignature=Unsigned;User=CORP\\jsmith;Hashes=SHA256=5B62...",
    "keylogging|10|Process accessed keyboard input process and wrote keystroke cache|SourceImage=C:\\Windows\\Temp\\inputsvc.exe;TargetImage=C:\\Windows\\explorer.exe;GrantedAccess=0x1410;OutputFile=C:\\ProgramData\\keys.dat;User=CORP\\jsmith;Computer=FIN-WKS-014",
    "process-hollowing|8|Remote thread created in suspended process|SourceImage=C:\\Windows\\Temp\\loader.exe;TargetImage=C:\\Windows\\System32\\svchost.exe;StartAddress=0x000001F40000;TargetProcessId=7440;SourceUser=CORP\\jsmith;Technique=ProcessHollowing",
    "process-injection|10|Process opened another process with write and thread rights|SourceImage=C:\\Windows\\Temp\\injector.exe;TargetImage=C:\\Windows\\System32\\explorer.exe;GrantedAccess=0x1F0FFF;CallTrace=ntdll.dll+kernel32.dll;User=CORP\\jsmith;Computer=FIN-WKS-014",
    "ransomware|23|High-volume file rename and encryption activity|Image=C:\\Windows\\Temp\\invoice_viewer.exe;FilesModified=2841;ExtensionAdded=.locked;Directories=Finance HR Shared;User=CORP\\jsmith;TimeWindowSeconds=47;CanaryFileModified=true",
    "rootkit|6|Kernel driver loaded from unusual path|Image=C:\\Windows\\Temp\\netflt.sys;SignatureStatus=Unsigned;StartType=System;ServiceName=NetFilter;User=NT AUTHORITY\\SYSTEM;Hashes=SHA256=CC18...",
    "scheduled-task-persistence|1|Scheduled task created from command line|Image=C:\\Windows\\System32\\schtasks.exe;CommandLine=schtasks /create /tn UpdateCheck /tr C:\\ProgramData\\update.exe /sc onlogon /ru SYSTEM;ParentImage=C:\\Windows\\System32\\cmd.exe;User=CORP\\jsmith;IntegrityLevel=High;TaskName=UpdateCheck",
    "screen-capture|1|Screen capture utility executed in user session|Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe;CommandLine=powershell.exe Add-Type System.Drawing;ParentImage=C:\\Windows\\System32\\cmd.exe;User=CORP\\jsmith;OutputFile=C:\\ProgramData\\screen.png;SessionId=2",
    "timestomping|2|File creation time changed to match system binary|Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe;TargetFilename=C:\\Windows\\Temp\\update.exe;PreviousCreationUtcTime=2026-08-08 03:11:02.200;CreationUtcTime=2021-04-12 09:14:44.000;User=CORP\\jsmith;Computer=FIN-WKS-014",
    "trojan-horse|1|User-launched document viewer spawned script interpreter|Image=C:\\Users\\jsmith\\Downloads\\InvoiceViewer.exe;CommandLine=InvoiceViewer.exe invoice_8821.pdf;ParentImage=C:\\Windows\\explorer.exe;ChildImage=C:\\Windows\\System32\\wscript.exe;User=CORP\\jsmith;SignatureStatus=Unsigned",
    "uac-bypass|13|Auto-elevated process launched unexpected child|Image=C:\\Windows\\System32\\fodhelper.exe;TargetObject=HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command;Details=C:\\Windows\\Temp\\update.exe;User=CORP\\jsmith;IntegrityLevel=High;ParentImage=C:\\Windows\\explorer.exe",
    "wiper-malware|1|Disk and recovery tooling invoked for destructive impact|Image=C:\\Windows\\System32\\wbadmin.exe;CommandLine=wbadmin delete catalog -quiet;ParentImage=C:\\Windows\\Temp\\wiper.exe;User=NT AUTHORITY\\SYSTEM;IntegrityLevel=System;Target=RecoveryCatalog",
    "wmi-execution|1|WMI provider spawned remote command|Image=C:\\Windows\\System32\\cmd.exe;CommandLine=cmd.exe /c C:\\Windows\\Temp\\stage.cmd;ParentImage=C:\\Windows\\System32\\wbem\\WmiPrvSE.exe;User=CORP\\adm.ops;IntegrityLevel=High;SourceIp=10.10.4.55"
  ]);

  register("mail", [
    "business-email-compromise|MessageTrace|Mailbox takeover payment request|From=cfo@corp.local;To=ap@corp.local;Subject=Urgent wire change;SourceIp=198.51.100.66;Authentication=SPF pass DKIM pass;ReplyTo=payments@external-example.com",
    "clone-phishing|SecureEmailGateway|Previously delivered message resent with changed attachment|From=hr@corp.local;To=employees@corp.local;Subject=Updated benefits enrollment;MessageId=<clone-8821@external>;OriginalMessageId=<hr-4401@corp>;Attachment=Benefits_Update.iso",
    "quishing|SecureEmailGateway|QR code detected in invoice attachment|From=billing@external-example.com;To=ap@corp.local;Subject=Invoice 88214 overdue;Attachment=invoice_88214.pdf;QrTarget=hxxps://login-check.example/qr;Verdict=suspicious",
    "smishing|SMSGateway|Credential lure delivered by SMS|From=+1-555-0199;To=+1-555-0148;Message=Your payroll account is locked. Verify at hxxps://payroll-check.example;ShortUrl=true;Carrier=External;Verdict=phishing",
    "spearphishing-attachment|SecureEmailGateway|Malicious attachment blocked|From=vendor@external-example.com;To=finance@corp.local;Subject=Revised purchase order;Attachment=PO_8821.xlsm;Sha256=4D52...;SandboxVerdict=malicious",
    "spearphishing-link|SecureEmailGateway|Credential-harvesting URL delivered|From=it-support@external-example.com;To=jsmith@corp.local;Subject=Password expires today;Url=hxxps://sso-corp-login.example/auth;UrlCategory=newly-registered;Verdict=phishing",
    "spearphishing-via-service|SaaSMessageAudit|External collaboration message carried lure|Service=Microsoft Teams;Sender=external.user@tenant.example;Recipient=jsmith@corp.local;Message=Shared security document;Url=hxxps://files-review.example;TenantRelationship=external;Verdict=suspicious",
    "whaling|SecureEmailGateway|Executive-targeted payment lure|From=ceo.office@external-example.com;To=cfo@corp.local;Subject=Confidential acquisition payment;ReplyTo=legal-advisor@example.net;SourceIp=203.0.113.70;Verdict=executive-impersonation"
  ]);

  register("identity", [
    "consent-and-approval-manipulation|AuditLogs|High-risk approval granted after external request|actor=global.admin@corp.local;target=Finance Automation;operation=Grant admin consent;permissions=Mail.ReadWrite Files.ReadWrite.All;sourceIp=198.51.100.80;result=success",
    "help-desk-impersonation|HelpDeskAudit|MFA method reset through support workflow|ticket=HD-88421;requester=cfo@corp.local;agent=helpdesk.agent;action=Reset MFA and issue temporary access pass;verification=knowledge-based only;sourceIp=203.0.113.14",
    "pretexting|HelpDeskAudit|Sensitive access request used fabricated business context|ticket=HD-88502;requester=contractor@example.net;claimedManager=cfo@corp.local;action=Request VPN enrollment;verification=manager callback failed;status=escalated",
    "vishing|VoiceSecurity|Caller requested credential or MFA action|caller=+1-555-0199;callee=helpdesk queue;displayName=Security Operations;action=Request password reset;voiceRisk=synthetic-voice suspected;durationSeconds=242;recordingId=call-78211"
  ]);

  register("web", [
    "clickfix-social-engineering|WAF-1204|Fake browser verification instructed command execution|method=GET;path=/verify/browser;query=step=copy-powershell;status=200;clientIp=198.51.100.41;userAgent=Chrome/122;matchedData=clipboard command prompt lure",
    "drive-by-compromise|WAF-1189|Compromised page redirected browser to exploit content|method=GET;path=/news/article;query=ref=search;status=302;clientIp=10.10.4.55;userAgent=Chrome/118;matchedData=redirect to hxxps://cdn-update.example/landing",
    "pharming|DNS-POISON|Trusted hostname resolved to unauthorized address|method=DNS;path=portal.corp.local;query=A;status=NOERROR;clientIp=10.10.4.55;userAgent=resolver;matchedData=answer 198.51.100.99 expected 10.10.1.20",
    "watering-hole|WAF-1189|Frequently visited site served injected script|method=GET;path=/industry/updates;query=campaign=summer;status=200;clientIp=10.10.4.55;userAgent=Chrome/118;matchedData=script src hxxps://cdn-check.example/p.js",
    "api-broken-object-authorization|WAF-BOLA|Authenticated user requested another account object|method=GET;path=/api/v2/accounts/8842;query=include=transactions;status=200;clientIp=10.10.4.55;userAgent=mobile-app/6.2;matchedData=token subject 7711 requested object 8842",
    "api-mass-assignment|WAF-MASS|API request supplied server-controlled properties|method=PATCH;path=/api/v2/users/7711;query=role=admin&isVerified=true;status=200;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=unexpected fields role isVerified",
    "authentication-bypass|WAF-AUTH|Protected endpoint reached without valid authentication|method=GET;path=/admin/export;query=debug=true;status=200;clientIp=203.0.113.44;userAgent=curl/8.4.0;matchedData=session missing authorization skipped",
    "command-injection|WAF-CMDI|Shell metacharacters reached command-backed parameter|method=POST;path=/tools/ping;query=host=127.0.0.1%3Bwhoami;status=500;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=semicolon whoami",
    "cross-site-request-forgery|WAF-CSRF|State-changing request lacked valid anti-CSRF token|method=POST;path=/account/email;query=newEmail=attacker@example.net;status=200;clientIp=10.10.4.55;userAgent=Chrome/118;matchedData=Origin external.example token missing",
    "cross-site-scripting|WAF-XSS|Script payload supplied to reflected parameter|method=GET;path=/search;query=q=%3Cscript%3Efetch('/session')%3C/script%3E;status=403;clientIp=198.51.100.77;userAgent=Chrome/118;matchedData=script tag fetch",
    "file-inclusion|WAF-LFI|File parameter attempted local file inclusion|method=GET;path=/view;query=template=../../../../etc/passwd;status=403;clientIp=198.51.100.77;userAgent=curl/8.4.0;matchedData=path traversal to etc passwd",
    "graphql-abuse|WAF-GQL|GraphQL request used deep aliases and introspection|method=POST;path=/graphql;query=query=IntrospectionQuery depth=18 aliases=220;status=200;clientIp=198.51.100.77;userAgent=graphql-client/1.4;matchedData=high depth alias count introspection",
    "host-header-injection|WAF-HOST|Untrusted Host header influenced reset link|method=POST;path=/password/reset;query=user=jsmith;status=202;clientIp=198.51.100.77;userAgent=Chrome/118;matchedData=Host evil.example X-Forwarded-Host evil.example",
    "http-request-smuggling|WAF-SMUGGLE|Conflicting message-length headers observed|method=POST;path=/;query=Content-Length=44 Transfer-Encoding=chunked;status=400;clientIp=198.51.100.77;userAgent=custom;matchedData=CL.TE ambiguity trailing request",
    "http-response-splitting|WAF-CRLF|CRLF characters supplied to response header parameter|method=GET;path=/redirect;query=url=%0d%0aSet-Cookie:admin=true;status=400;clientIp=198.51.100.77;userAgent=curl/8.4.0;matchedData=encoded CRLF response header",
    "insecure-deserialization|WAF-DESER|Serialized object marker reached application endpoint|method=POST;path=/api/session/restore;query=body=rO0ABXNyABFqYXZh;status=500;clientIp=198.51.100.77;userAgent=Java/1.8;matchedData=Java serialization magic bytes",
    "jwt-token-attack|WAF-JWT|JWT accepted with unsafe algorithm or changed claims|method=GET;path=/api/admin;query=Authorization Bearer eyJhbGciOiJub25lIn0;status=200;clientIp=198.51.100.77;userAgent=curl/8.4.0;matchedData=alg none role admin",
    "ldap-injection|WAF-LDAP|LDAP filter metacharacters supplied to login|method=POST;path=/login;query=user=*)(uid=*))(%7C(uid=*;status=500;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=LDAP wildcard filter injection",
    "nosql-injection|WAF-NOSQL|JSON operator supplied where scalar credential expected|method=POST;path=/api/login;query=username=admin&password[$ne]=x;status=200;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=MongoDB $ne operator",
    "open-redirect|WAF-REDIRECT|External destination accepted by redirect parameter|method=GET;path=/continue;query=next=https://login-lookalike.example;status=302;clientIp=198.51.100.77;userAgent=Chrome/118;matchedData=Location external untrusted host",
    "path-traversal|WAF-PATH|Encoded parent-directory traversal requested|method=GET;path=/download;query=file=..%2f..%2f..%2fetc%2fshadow;status=403;clientIp=198.51.100.77;userAgent=curl/8.4.0;matchedData=encoded traversal etc shadow",
    "prototype-pollution|WAF-PROTO|Prototype property supplied in JSON body|method=POST;path=/api/profile;query=__proto__[isAdmin]=true;status=500;clientIp=198.51.100.77;userAgent=node-fetch/3.3;matchedData=__proto__ constructor prototype",
    "race-condition-attack|WAF-RACE|Concurrent requests changed the same state repeatedly|method=POST;path=/api/coupon/redeem;query=code=SUMMER50;status=200;clientIp=198.51.100.77;userAgent=Turbo-Intruder;matchedData=48 requests in 120 milliseconds",
    "server-side-request-forgery|WAF-SSRF|Application fetched link-local metadata address|method=POST;path=/api/fetch;query=url=http://169.254.169.254/latest/meta-data/iam/security-credentials/;status=200;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=link-local metadata endpoint",
    "template-injection|WAF-SSTI|Template expression executed in server-side render input|method=POST;path=/preview;query=name={{7*7}};status=200;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=response contained 49",
    "unrestricted-file-upload|WAF-UPLOAD|Executable server-side file uploaded as image|method=POST;path=/api/avatar;query=filename=shell.aspx&contentType=image/jpeg;status=201;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=ASPX content in image upload",
    "web-cache-deception|WAF-CACHE|Authenticated content cached under static-looking path|method=GET;path=/account/profile.css;query=;status=200;clientIp=198.51.100.77;userAgent=Chrome/118;matchedData=Cache-Control public Set-Cookie present",
    "web-cache-poisoning|WAF-POISON|Unkeyed header altered cached response|method=GET;path=/home;query=;status=200;clientIp=198.51.100.77;userAgent=Chrome/118;matchedData=X-Forwarded-Host evil.example cache HIT",
    "web-shell|WAF-WEBSHELL|Server-side script accepted command parameter|method=POST;path=/uploads/image.aspx;query=cmd=whoami;status=200;clientIp=198.51.100.77;userAgent=curl/8.4.0;matchedData=uploaded ASPX spawned cmd.exe",
    "xml-external-entity-injection|WAF-XXE|XML document declared external entity|method=POST;path=/api/import/xml;query=DOCTYPE foo ENTITY xxe SYSTEM file:///etc/passwd;status=500;clientIp=198.51.100.77;userAgent=python-requests/2.31.0;matchedData=DOCTYPE external entity SYSTEM"
  ]);

  register("network", [
    "arp-spoofing|SURICATA-ARP|Conflicting ARP ownership observed|srcIp=10.10.4.66;dstIp=10.10.4.1;proto=ARP;srcPort=0;dstPort=0;detail=10.10.4.1 claimed by 00:11:22:33:44:55 and 66:77:88:99:aa:bb",
    "bgp-hijacking|BGP-RPKI|Route origin changed to invalid ASN|srcIp=192.0.2.10;dstIp=192.0.2.1;proto=BGP;srcPort=179;dstPort=179;detail=prefix 203.0.113.0/24 origin AS64599 RPKI invalid expected AS64500",
    "dhcp-starvation|SURICATA-DHCP|High-rate DHCP DISCOVER with changing client IDs|srcIp=0.0.0.0;dstIp=255.255.255.255;proto=UDP;srcPort=68;dstPort=67;detail=312 DISCOVER 312 unique chaddr in 30 seconds",
    "dns-amplification|SURICATA-DNS|Large DNS responses sent to spoofed victim|srcIp=203.0.113.53;dstIp=198.51.100.10;proto=UDP;srcPort=53;dstPort=49211;detail=query ANY responseBytes 4096 requestBytes 60 amplification 68x",
    "dns-cache-poisoning|DNS-AUDIT|Resolver cached answer from unexpected authority|srcIp=198.51.100.53;dstIp=10.10.1.53;proto=UDP;srcPort=53;dstPort=53022;detail=portal.corp.local answer 198.51.100.99 unsolicited authority mismatch",
    "dns-tunneling|SURICATA-DNS|High-entropy subdomains with TXT responses|srcIp=10.10.4.55;dstIp=10.10.1.53;proto=UDP;srcPort=53114;dstPort=53;detail=184 unique subdomains avgLabelLength 52 queryType TXT domain data-sync.example",
    "icmp-flood|SURICATA-ICMP|Excessive ICMP echo request volume|srcIp=198.51.100.77;dstIp=203.0.113.22;proto=ICMP;srcPort=0;dstPort=0;detail=148220 echo requests in 60 seconds zero replies",
    "ip-fragmentation-attack|SURICATA-FRAG|Overlapping IPv4 fragments detected|srcIp=198.51.100.77;dstIp=203.0.113.22;proto=IPv4;srcPort=0;dstPort=0;detail=fragment id 0x4a21 overlap 24 bytes tiny fragments 19",
    "llmnr-nbt-ns-poisoning|SURICATA-LLMNR|LLMNR response from non-approved responder|srcIp=10.10.4.66;dstIp=224.0.0.252;proto=UDP;srcPort=5355;dstPort=5355;detail=query FILESRV response 10.10.4.66 followed by NTLM authentication",
    "mac-flooding|SWITCH-CAM|CAM table learned excessive MAC addresses on one port|srcIp=0.0.0.0;dstIp=0.0.0.0;proto=Ethernet;srcPort=0;dstPort=0;detail=switch SW-ACCESS-04 port Gi1/0/18 learned 4096 MACs in 12 seconds",
    "man-in-the-browser|PROXY-SESSION|Authenticated transaction values changed in browser session|srcIp=10.10.4.55;dstIp=203.0.113.20;proto=HTTPS;srcPort=51842;dstPort=443;detail=beneficiary changed after page render session cookie unchanged browser extension injected",
    "man-in-the-middle|SURICATA-TLS|TLS certificate changed within established destination baseline|srcIp=10.10.4.55;dstIp=203.0.113.20;proto=TLS;srcPort=51842;dstPort=443;detail=issuer Local Proxy fingerprint changed certificate not trusted",
    "network-sniffing|SWITCH-SPAN|Unauthorized promiscuous interface and mirror configuration|srcIp=10.10.4.55;dstIp=0.0.0.0;proto=Ethernet;srcPort=0;dstPort=0;detail=host FIN-WKS-014 interface Ethernet0 promiscuous true SPAN destination unapproved",
    "ntlm-relay|SURICATA-NTLM|NTLM authentication relayed between hosts|srcIp=10.10.4.66;dstIp=10.10.1.10;proto=SMB;srcPort=51144;dstPort=445;detail=NTLM challenge reused victim 10.10.4.55 target DC01 signing not required",
    "ntp-amplification|SURICATA-NTP|NTP monlist-style amplification traffic|srcIp=203.0.113.123;dstIp=198.51.100.10;proto=UDP;srcPort=123;dstPort=49882;detail=requestBytes 8 responseBytes 4680 amplification 585x mode 7",
    "ping-of-death|SURICATA-ICMP|Oversized reassembled ICMP packet|srcIp=198.51.100.77;dstIp=203.0.113.22;proto=ICMP;srcPort=0;dstPort=0;detail=reassembledLength 65596 exceeds IPv4 maximum fragmentCount 88",
    "port-scanning|SURICATA-SCAN|One source contacted many destination ports|srcIp=198.51.100.77;dstIp=203.0.113.22;proto=TCP;srcPort=51842;dstPort=multiple;detail=1024 distinct ports in 18 seconds SYN only 12 SYN-ACK",
    "rdp-session-hijacking|WINDOWS-RDP|Existing RDP session reconnected by different account|srcIp=10.10.4.55;dstIp=10.10.1.20;proto=RDP;srcPort=51991;dstPort=3389;detail=sessionId 7 disconnected user jsmith reconnected user adm.ops without new network logon",
    "rogue-dhcp|DHCP-SNOOP|DHCP OFFER received on untrusted access port|srcIp=10.10.4.66;dstIp=255.255.255.255;proto=UDP;srcPort=67;dstPort=68;detail=serverIdentifier 10.10.4.66 gateway 10.10.4.66 switchport Gi1/0/18 untrusted",
    "session-hijacking|PROXY-SESSION|Session token reused from new network and device|srcIp=198.51.100.88;dstIp=203.0.113.20;proto=HTTPS;srcPort=52331;dstPort=443;detail=sessionId a91f user jsmith previousIp 10.10.4.55 deviceFingerprint changed",
    "slowloris|SURICATA-HTTP|Many incomplete HTTP requests held open|srcIp=198.51.100.77;dstIp=203.0.113.15;proto=HTTP;srcPort=multiple;dstPort=80;detail=850 concurrent connections headers incomplete averageDuration 119 seconds",
    "smb-relay|SURICATA-SMB|SMB authentication relayed to second host|srcIp=10.10.4.66;dstIp=10.10.1.10;proto=SMB;srcPort=51144;dstPort=445;detail=NTLM user CORP\\jsmith victim 10.10.4.55 target DC01 signing false",
    "ssh-session-hijacking|SSH-AUDIT|Existing SSH control socket used by another process|srcIp=10.10.4.55;dstIp=10.10.1.20;proto=SSH;srcPort=51912;dstPort=22;detail=controlPath /tmp/ssh-AbC socket owner jsmith client process unknown session reused",
    "ssl-stripping|PROXY-TLS|HTTPS navigation downgraded to HTTP|srcIp=10.10.4.55;dstIp=203.0.113.20;proto=HTTP;srcPort=51842;dstPort=80;detail=originalUrl https://bank.example redirect chain removed HSTS via gateway 10.10.4.66",
    "tcp-syn-flood|SURICATA-SYN|High-rate SYN packets without completed handshakes|srcIp=198.51.100.0/24;dstIp=203.0.113.22;proto=TCP;srcPort=multiple;dstPort=443;detail=928441 SYN in 60 seconds completionRate 0.2 percent",
    "udp-flood|SURICATA-UDP|High-volume UDP packets saturated service|srcIp=198.51.100.0/24;dstIp=203.0.113.22;proto=UDP;srcPort=multiple;dstPort=443;detail=1.8 million packets in 60 seconds 4.2 Gbps",
    "vlan-hopping|SWITCH-DTP|Unexpected trunk negotiation from access port|srcIp=0.0.0.0;dstIp=0.0.0.0;proto=DTP;srcPort=0;dstPort=0;detail=switch SW-ACCESS-04 port Gi1/0/18 mode changed access to trunk nativeVlan 1 allowedVlans all"
  ]);

  register("cloud", [
    "additional-cloud-credential-persistence|iam.amazonaws.com|CreateAccessKey|principal=arn:aws:iam::123456789012:user/buildsvc;sourceIp=198.51.100.77;targetUser=buildsvc;accessKeyId=AKIA...9Q2;userAgent=aws-cli/2.15;result=Success",
    "additional-cloud-role-persistence|iam.amazonaws.com|AttachUserPolicy|principal=arn:aws:iam::123456789012:user/buildsvc;sourceIp=198.51.100.77;targetUser=buildsvc;policyArn=arn:aws:iam::aws:policy/AdministratorAccess;userAgent=aws-cli/2.15;result=Success",
    "cloud-access-key-theft|sts.amazonaws.com|GetCallerIdentity with exposed key|principal=arn:aws:iam::123456789012:user/deploy;sourceIp=203.0.113.81;accessKeyId=AKIA...4TR;region=us-east-1;userAgent=aws-cli/2.15;firstSeenSource=true",
    "cloud-account-takeover|signin.amazonaws.com|ConsoleLogin|principal=arn:aws:iam::123456789012:user/cloudadmin;sourceIp=203.0.113.82;mfaUsed=No;result=Success;userAgent=Chrome/118;firstSeenCountry=true",
    "cloud-cryptojacking|ec2.amazonaws.com|RunInstances|principal=arn:aws:iam::123456789012:user/devops;sourceIp=198.51.100.77;instanceType=p4d.24xlarge;count=12;region=ap-south-2;imageId=ami-crypto01",
    "cloud-iam-privilege-escalation|iam.amazonaws.com|PutUserPolicy|principal=arn:aws:iam::123456789012:user/buildsvc;sourceIp=198.51.100.77;targetUser=buildsvc;policyAction=iam:*;policyResource=*;result=Success",
    "cloud-logging-disablement|cloudtrail.amazonaws.com|StopLogging|principal=arn:aws:iam::123456789012:user/cloudadmin;sourceIp=198.51.100.77;trailName=organization-trail;region=us-east-1;userAgent=aws-cli/2.15;result=Success",
    "cloud-metadata-service-abuse|vpcflow.amazonaws.com|Metadata endpoint accessed from workload|principal=arn:aws:sts::123456789012:assumed-role/WebRole/i-0abc;sourceIp=10.20.4.18;destinationIp=169.254.169.254;path=/latest/meta-data/iam/security-credentials/;httpStatus=200;process=curl",
    "cloud-region-evasion|ec2.amazonaws.com|RunInstances in unused region|principal=arn:aws:iam::123456789012:user/devops;sourceIp=198.51.100.77;region=me-central-1;instanceType=t3.large;baselineRegion=false;count=4",
    "cloud-snapshot-theft|ec2.amazonaws.com|ModifySnapshotAttribute|principal=arn:aws:iam::123456789012:user/backupsvc;sourceIp=198.51.100.77;snapshotId=snap-0a12bc34;createVolumePermission=all;encrypted=false;result=Success",
    "cloud-secrets-store-theft|secretsmanager.amazonaws.com|GetSecretValue from an unusual source|principal=arn:aws:iam::123456789012:user/buildsvc;sourceIp=198.51.100.77;secretId=prod/database/admin;versionStage=AWSCURRENT;userAgent=aws-cli/2.15;firstSeenSource=true;result=Success",
    "public-storage-bucket-exposure|s3.amazonaws.com|PutBucketPolicy|principal=arn:aws:iam::123456789012:user/webdeploy;sourceIp=198.51.100.77;bucket=corp-customer-exports;principalGranted=*;actionGranted=s3:GetObject;blockPublicAccess=false",
    "saas-data-exfiltration|graph.microsoft.com|Large export through SaaS API|principal=jsmith@corp.local;sourceIp=198.51.100.77;resource=SharePoint;operation=DriveItemDownload;objects=18420;bytes=9284412200;appId=GraphExplorer",
    "serverless-function-abuse|lambda.amazonaws.com|UpdateFunctionCode|principal=arn:aws:iam::123456789012:user/devops;sourceIp=198.51.100.77;functionName=invoice-processor;codeSha256=8f2a...;runtime=python3.12;result=Success"
  ]);

  register("kubernetes", [
    "container-api-exposure|docker.audit|Unauthenticated Docker API container creation|verb=POST;path=/containers/create;user=system:anonymous;sourceIp=198.51.100.77;image=alpine;command=sh -c mount /host;responseCode=201",
    "container-escape|falco|Container process accessed host namespace|rule=Contact K8S API Server From Container;pod=payments-7d9f;namespace=prod;user=root;process=nsenter;arguments=--target 1 --mount --uts --ipc --net --pid",
    "kubernetes-admission-controller-abuse|k8s.audit|MutatingWebhookConfiguration modified|verb=patch;resource=mutatingwebhookconfigurations;name=pod-injector;user=system:serviceaccount:dev:builder;sourceIp=10.30.4.18;responseCode=200;patch=webhook clientConfig changed",
    "kubernetes-api-abuse|k8s.audit|Privileged pod created through API|verb=create;resource=pods;name=debug-host;namespace=prod;user=system:serviceaccount:dev:builder;sourceIp=10.30.4.18;responseCode=201;spec=privileged true hostPID true",
    "kubernetes-secrets-theft|k8s.audit|Secrets listed across production namespace|verb=list;resource=secrets;namespace=prod;user=system:serviceaccount:dev:builder;sourceIp=10.30.4.18;responseCode=200;userAgent=curl/8.4.0"
  ]);

  register("physical", [
    "bluetooth-exploitation|BT-IDS|Unauthorized Bluetooth service access|sensor=BT-SENSOR-04;deviceMac=66:77:88:99:AA:BB;targetMac=00:11:22:33:44:55;profile=OBEX-PUSH;action=file-transfer;result=allowed;rssi=-42",
    "evil-twin-wi-fi|WLC-WIDS|Duplicate SSID with unauthorized BSSID|controller=WLC-01;ssid=CORP-WIFI;authorizedBssid=00:11:22:33:44:55;rogueBssid=66:77:88:99:AA:BB;channel=6;security=WPA2;clients=7",
    "rfid-cloning|PACS-AUDIT|Same badge used at impossible locations|controller=PACS-01;badgeId=E1048821;firstReader=BLDG-A-ENTRY;secondReader=DC-ROOM-02;elapsedSeconds=18;distanceMeters=940;result=granted",
    "rogue-access-point|WLC-WIDS|Unauthorized access point connected to corporate network|controller=WLC-01;bssid=66:77:88:99:AA:BB;ssid=Free-Corp-WiFi;switchPort=SW-04/Gi1/0/18;channel=11;wiredMac=66:77:88:99:AA:BC;classification=rogue",
    "tailgating|PACS-VIDEO|Door held open after single badge grant|controller=PACS-01;door=BLDG-A-ENTRY;badgeId=E1048821;badgeCount=1;peopleCount=2;doorOpenSeconds=18;videoEvent=multiple-person-entry",
    "usb-drop-attack|DEVICE-CONTROL|New removable device launched executable|computer=FIN-WKS-014;user=CORP\\jsmith;deviceId=USBSTOR\\VID_0781;volumeLabel=PAYROLL;file=Payroll_Adjustment.exe;sha256=7A14...;action=executed",
    "wi-fi-deauthentication|WLC-WIDS|Burst of spoofed deauthentication frames|controller=WLC-01;ssid=CORP-WIFI;bssid=00:11:22:33:44:55;sourceMac=66:77:88:99:AA:BB;reasonCode=7;frames=428;timeWindowSeconds=10",
    "wpa-handshake-capture|WLC-WIDS|Repeated deauthentication followed by EAPOL handshakes|controller=WLC-01;ssid=CORP-WIFI;bssid=00:11:22:33:44:55;station=10:20:30:40:50:60;deauthFrames=72;eapolM1M4=8;sourceMac=66:77:88:99:AA:BB"
  ]);

  register("supply", [
    "adversarial-examples|ML-GATEWAY|Model input caused high-confidence label flip|model=fraud-v4.2;requestId=ml-88214;inputHash=sha256:4a91...;baselineLabel=fraud;observedLabel=legitimate;confidence=0.998;perturbationScore=0.031",
    "ci-cd-pipeline-compromise|CI-AUDIT|Workflow modified and secrets accessed by new runner|repository=corp/payments-api;actor=contractor1;workflow=.github/workflows/release.yml;change=pull_request_target plus secrets;runner=self-hosted-unknown;sourceIp=198.51.100.77",
    "deepfake-social-engineering|VOICE-RISK|Synthetic media indicators in executive call|callId=call-88214;claimedIdentity=CFO;destination=AP Desk;voiceCloneScore=0.97;liveness=failed;request=urgent payment change;sourceNumber=+1-555-0199",
    "dependency-confusion|PACKAGE-AUDIT|Public package selected over internal namespace|package=corp-auth-utils;requestedVersion=>=2.4.0;resolvedVersion=99.0.1;resolvedRegistry=registry.npmjs.org;expectedRegistry=npm.corp.local;integrity=sha512-4A91...",
    "firmware-supply-chain-attack|FIRMWARE-VERIFY|Device firmware signature or hash failed validation|deviceModel=EDGE-500;firmwareVersion=8.4.2;imageHash=sha256:8c14...;expectedHash=sha256:1a02...;signatureStatus=invalid;updateSource=mirror-03.example",
    "model-poisoning|ML-PIPELINE|Training dataset changed outside approved pipeline|model=fraud-v4.3;dataset=s3://ml-prod/training/2026-08;addedRows=18422;labelDrift=0.31;actor=buildsvc;sourceIp=198.51.100.77;approvalId=missing",
    "prompt-injection|AI-GATEWAY|Untrusted content attempted instruction override and tool use|requestId=ai-88214;user=jsmith;source=document-upload;pattern=ignore previous instructions;toolRequested=send_email;destination=external@example.net;policyAction=blocked",
    "software-supply-chain-compromise|BUILD-PROVENANCE|Released artifact did not match trusted build provenance|repository=corp/desktop-agent;release=6.4.1;artifactHash=sha256:cc18...;provenanceHash=sha256:aa02...;signer=release-bot;builderId=untrusted-runner-22",
    "typosquatting-package|PACKAGE-AUDIT|Lookalike package installed from public registry|requestedPackage=requests;installedPackage=reqeusts;version=2.31.0;registry=pypi.org;publisherAgeDays=2;postInstallScript=true;sha256=9d42...",
    "zero-day-exploitation|IPS-UNKNOWN|Exploit-like behavior without a known CVE signature|target=web-prod-03;service=HTTPS;sourceIp=198.51.100.77;request=/api/parser;anomaly=memory corruption followed by child process;childProcess=/bin/sh;signature=generic exploit behavior;action=alert"
  ]);

  function encodeFields(fields) {
    return Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, value]));
  }

  function renderRaw(profile, title) {
    const f = profile.fields;
    const timestamp = "2026-08-08T03:22:41.550Z";
    if (profile.type === "windows" || profile.type === "sysmon") {
      const channel = profile.type === "sysmon" ? "Microsoft-Windows-Sysmon/Operational" : "Security";
      const source = profile.type === "sysmon" ? "Microsoft-Windows-Sysmon" : "Microsoft-Windows-Security-Auditing";
      return {
        source: `${source} — Event ${profile.code}`,
        raw: `Log Name:      ${channel}\nSource:        ${source}\nEvent ID:      ${profile.code}\nLevel:         Information\nComputer:      ${f.Computer || "FIN-WKS-014.corp.local"}\nTimeCreated:   ${timestamp}\nDescription:   ${profile.operation}.\n${Object.entries(f).map(([key, value]) => `               ${key}: ${value}`).join("\n")}`
      };
    }
    if (profile.type === "identity") {
      return {
        source: `${profile.code} — identity and authentication audit`,
        raw: JSON.stringify({
          timestamp,
          event_type: profile.code,
          operation: profile.operation,
          actor: f.actor || f.user || f.account || "unknown",
          source_ip: f.sourceIp,
          target: f.target || f.resource || f.service || f.account,
          result: f.result || "observed",
          risk_context: title,
          details: encodeFields(f)
        }, null, 2)
      };
    }
    if (profile.type === "web") {
      return {
        source: `Reverse proxy / WAF — ${profile.code}`,
        raw: `#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)\n2026-08-08 03:22:41 ${f.clientIp} ${f.method} ${f.path} ${f.query || "-"} ${f.status} ${f.userAgent}\n${JSON.stringify({ timestamp, event_type: "waf", rule_id: profile.code, rule_name: title, action: f.status === "403" ? "blocked" : "logged", client_ip: f.clientIp, matched_data: f.matchedData }, null, 2)}`
      };
    }
    if (profile.type === "network") {
      return {
        source: `Network detection telemetry — ${profile.code}`,
        raw: JSON.stringify({ timestamp, event_type: "alert", src_ip: f.srcIp, src_port: Number(f.srcPort) || 0, dest_ip: f.dstIp, dest_port: Number(f.dstPort) || 0, proto: f.proto, alert: { signature: title, signature_id: profile.code, category: profile.operation, severity: 2 }, observation: f.detail }, null, 2)
      };
    }
    if (profile.type === "mail") {
      return {
        source: `${profile.code} — mail and messaging telemetry`,
        raw: `Timestamp: ${timestamp}\nEvent: ${profile.operation}\n${Object.entries(f).map(([key, value]) => `${key}: ${value}`).join("\n")}`
      };
    }
    if (profile.type === "cloud") {
      return {
        source: `Cloud audit event — ${profile.code}`,
        raw: JSON.stringify({ eventVersion: "1.09", eventTime: timestamp, eventSource: profile.code, eventName: profile.operation, userIdentity: { principalId: f.principal }, sourceIPAddress: f.sourceIp, userAgent: f.userAgent || "console.amazonaws.com", requestParameters: encodeFields(f), responseElements: { result: f.result || "Success" } }, null, 2)
      };
    }
    if (profile.type === "kubernetes") {
      return {
        source: `${profile.code} — container / Kubernetes audit`,
        raw: JSON.stringify({ kind: "Event", apiVersion: "audit.k8s.io/v1", level: "RequestResponse", auditID: "e14f8a21-8821-4c01", stageTimestamp: timestamp, verb: f.verb, user: { username: f.user }, sourceIPs: [f.sourceIp], objectRef: { resource: f.resource, namespace: f.namespace, name: f.name }, requestURI: f.path, responseStatus: { code: Number(f.responseCode) || 200 }, observation: profile.operation, details: encodeFields(f) }, null, 2)
      };
    }
    if (profile.type === "physical") {
      return {
        source: `${profile.code} — physical / wireless controller`,
        raw: `timestamp=${timestamp} event="${profile.operation}"\n${Object.entries(f).map(([key, value]) => `${key}="${value}"`).join("\n")}`
      };
    }
    return {
      source: `${profile.code} — build, package, or emerging-tech audit`,
      raw: JSON.stringify({ timestamp, event_type: profile.code, finding: title, observation: profile.operation, severity: "high", details: encodeFields(f) }, null, 2)
    };
  }

  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined) item.textContent = text;
    return item;
  }

  function render() {
    const slug = location.pathname.split("/").pop().replace(/\.html$/, "");
    if (suppliedEvidenceSlugs.has(slug)) return;
    const profile = profiles.get(slug);
    const section = document.querySelector("#log-examples > div:last-child");
    if (!profile || !section) return;

    const title = document.querySelector(".detail-title-grid h1")?.textContent.trim() || slug;
    const rendered = renderRaw(profile, title);
    section.querySelector(":scope > h2").textContent = "Production-shaped log examples";
    const navLabel = document.querySelector('.study-nav a[href="#log-examples"]');
    if (navLabel) {
      const number = navLabel.querySelector("b")?.outerHTML || "";
      navLabel.innerHTML = `${number}Production-shaped logs`;
    }

    const wrapper = node("div", "production-evidence-pack attack-specific-evidence-pack");
    const intro = node("div", "production-evidence-intro");
    intro.append(node("span", "", "ATTACK-SPECIFIC EVIDENCE · NATIVE SOURCE SHAPE"));
    intro.append(node("strong", "", `Telemetry that directly supports the ${title} hypothesis.`));
    intro.append(node("p", "", `This record uses the field layout of the telemetry source most likely to observe this behavior. Values are sanitized training data. Detect the behavior through the listed pivots and correlation—not by matching this example literally.`));

    const stack = node("div", "log-sample-stack production-log-stack");
    const sample = node("div", "log-sample production-log-sample");
    const head = node("div", "log-sample-head");
    const source = node("div");
    source.append(node("span", "", "ATTACK-SPECIFIC RAW TELEMETRY"));
    source.append(node("strong", "", rendered.source));
    const copy = node("button", "copy-button", "COPY LOG");
    copy.type = "button";
    copy.setAttribute("data-copy-query", "");
    head.append(source, copy);
    sample.append(head);
    sample.append(node("p", "", profile.operation));
    const pre = node("pre");
    pre.append(node("code", "", rendered.raw));
    sample.append(pre);

    const guide = node("div", "log-interpretation production-log-guide");
    guide.append(node("strong", "", "DETECTION PIVOTS — START HERE"));
    const pivots = node("ul", "production-pivots");
    const pivotEntries = Object.entries(profile.fields).slice(0, 6);
    pivotEntries.forEach(([key, value]) => pivots.append(node("li", "", `${key}=${value}`)));
    guide.append(pivots);
    const correlate = node("p");
    correlate.append(node("b", "", "CORRELATE NEXT: "));
    correlate.append(document.createTextNode(`Join this event to identity, source, target, process, network, and state-change telemetry within the same time window. Confirm that the sequence supports ${title}; a single record is not proof.`));
    guide.append(correlate);
    sample.append(guide);
    stack.append(sample);
    wrapper.append(intro, stack);

    const warning = section.querySelector(":scope > .evidence-warning");
    if (warning) {
      warning.querySelector("strong").textContent = "SCHEMA-SHAPED COMPANION EXAMPLES";
      warning.querySelector("p").textContent = "The examples after this attack-specific record remain sanitized companion data. Use the native-format record above as the primary learning reference.";
    }
    section.insertBefore(wrapper, warning || section.querySelector(":scope > .log-sample-stack"));
  }

  render();
})();
