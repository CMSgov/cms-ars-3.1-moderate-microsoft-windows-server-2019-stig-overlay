# encoding: UTF-8

include_controls "microsoft-windows-server-2019-stig-baseline" do

  control "V-92975" do
    title "Windows Server 2019 must automatically remove or disable temporary user accounts after 60 days."
    desc  "If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.
  
      Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.
      If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a CMS-defined time period of 60 days.
      To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
    desc  'check', "Review temporary user accounts for expiration dates.
      Determine if temporary user accounts are used and identify any that exist. If none exist, this is NA.
  
      Domain Controllers:
      Open \"PowerShell\".
      Enter \"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate\".
      If \"AccountExpirationDate\" has not been defined within 60 days for any temporary user account, this is a finding.
  
      Member servers and standalone systems:
      Open \"Command Prompt\".
      Run \"Net user [username]\", where [username] is the name of the temporary user account.
      If \"Account expires\" has not been defined within 60 days for any temporary user account, this is a finding."
    desc  'fix', "Configure temporary user accounts to automatically expire within 60 days.
      Domain accounts can be configured with an account expiration date, under \"Account\" properties.
      Local accounts can be configured to expire with the command \"Net user [username] /expires:[mm/dd/yyyy]\", where username is the name of the temporary user account.
      Delete any temporary user accounts that are no longer necessary."
  end

  control "V-92977" do
    title "Windows Server 2019 must automatically remove or disable emergency accounts after the crisis is resolved or within 24 hours."
    desc  "Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.
      Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.
      To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
    desc  'check', "Determine if emergency administrator accounts are used and identify any that exist. If none exist, this is NA.
      If emergency administrator accounts cannot be configured with an expiration date due to an ongoing crisis, the accounts must be disabled or removed when the crisis is resolved.
      If emergency administrator accounts have not been configured with an expiration date or have not been disabled or removed following the resolution of a crisis, this is a finding.
  
      Domain Controllers:
      Open \"PowerShell\".
      Enter \"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate\".
      If \"AccountExpirationDate\" has been defined and is not within 24 hours for an emergency administrator account, this is a finding.
  
      Member servers and standalone systems:
      Open \"Command Prompt\".
      Run \"Net user [username]\", where [username] is the name of the emergency account.
      If \"Account expires\" has been defined and is not within 24 hours for an emergency administrator account, this is a finding."
    desc  'fix', "Remove emergency administrator accounts after a crisis has been resolved or configure the accounts to automatically expire within 24 hours.
      Domain accounts can be configured with an account expiration date, under \"Account\" properties.
      Local accounts can be configured to expire with the command \"Net user [username] /expires:[mm/dd/yyyy]\", where username is the name of the temporary user account."
  end

  control "V-93019" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93021" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93023" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93143" do
    title "Windows Server 2019 must have the period of time before the bad logon counter is reset configured to 120 minutes or greater."
    desc  'check', "Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".
      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.
      If the \"Reset account lockout counter after\" value is less than \"120\" minutes, this is a finding.
      For server core installations, run the following command:
      Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
      If \"ResetLockoutCount\" is less than \"120\" in the file, this is a finding."
    desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> \"Reset account lockout counter after\" to at least \"120\" minutes."
  end

  control "V-93145" do
    title "Windows Server 2019 account lockout duration must be configured to 60 minutes or greater."
    desc  'check', "Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".
      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.
      If the \"Account lockout duration\" is less than \"60\" minutes (excluding \"0\"), this is a finding.
  
      For server core installations, run the following command:
      Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
      If \"LockoutDuration\" is less than \"60\" (excluding \"0\") in the file, this is a finding.
      Configuring this to \"0\", requiring an administrator to unlock the account, is more restrictive and is not a finding."
    desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> \"Account lockout duration\" to \"60\" minutes or greater.
      A value of \"0\" is also acceptable, requiring an administrator to unlock the account."
  end

  control "V-93147" do
    desc  'check', "If the following registry value does not exist or is not configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

      Value Name: LegalNoticeText

      Value Type: REG_SZ
      Value: See message text below

    * This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
    * This system is provided for Government authorized use only.
    * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
    * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
    * By using this system, you understand and consent to the following:  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purposes."
    desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Interactive Logon: Message text for users attempting to log on\" to the following:

    * This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
    * This system is provided for Government authorized use only.
    * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
    * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
    * By using this system, you understand and consent to the following:  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purposes."
  end

  control "V-93149" do
    desc  'check', "If the following registry value does not exist or is not configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

      Value Name: LegalNoticeCaption

      Value Type: REG_SZ
      Value: See message title options below

      \"CMS Notice and Consent Banner\", \"US Department of Health and Human Services Warning Statement\", or an organization-defined equivalent.
      If an organization-defined title is used, it can in no case contravene or modify the language of the banner text required in WN19-SO-000150.
      Automated tools may only search for the titles defined above. If an organization-defined title is used, a manual review will be required."
    desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Interactive Logon: Message title for users attempting to log on\" to \"CMS Notice and Consent Banner\", \"US Department of Health and Human Services Warning Statement\", or an organization-defined equivalent.
    If an organization-defined title is used, it can in no case contravene or modify the language of the message text required in WN19-SO-000150."
  end

  control "V-93183" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93185" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93187" do
    title "The Windows Server 2019 time service must synchronize with an appropriate CMS time source."
    desc  'check', "Review the Windows time service configuration.
    Open an elevated \"Command Prompt\" (run as administrator).
    Enter \"W32tm /query /configuration\".
    Domain-joined systems (excluding the domain controller with the PDC emulator role):
    If the value for \"Type\" under \"NTP Client\" is not \"NT5DS\", this is a finding.

    Other systems:
    If systems are configured with a \"Type\" of \"NTP\", including standalone systems and the domain controller with the PDC Emulator role, and do not have a CMS time server defined for \"NTPServer\", this is a finding.

    CMS-approved time servers include:
    - NIST Internet Time Servers (http://tf.nist.gov/tf-cgi/servers.cgi)
    - U.S. Naval Observatory Stratum-1 NTP Servers (http://tycho.usno.navy.mil/ntp.html); and
    - CMS designated internal NTP time servers providing an NTP Stratum-2 service to the above servers

    To determine the domain controller with the PDC Emulator role:
    Open \"PowerShell\".
    Enter \"Get-ADDomain | FT PDCEmulator\"."
    desc  'fix', "Configure the system to synchronize time with an appropriate CMS time source.
    Domain-joined systems use NT5DS to synchronize time from other systems in the domain by default.
    If the system needs to be configured to an NTP server, configure the system to point to an authorized time server by setting the policy value for Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers >> \"Configure Windows NTP Client\" to \"Enabled\", and configure the \"NtpServer\" field to point to an appropriate CMS time server.

    CMS-approved time servers include:
    - NIST Internet Time Servers (http://tf.nist.gov/tf-cgi/servers.cgi)
    - U.S. Naval Observatory Stratum-1 NTP Servers (http://tycho.usno.navy.mil/ntp.html); and
    - CMS designated internal NTP time servers providing an NTP Stratum-2 service to the above servers

    Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower-level servers will synchronize with an authorized time server in the hierarchy."
  end

  control "V-93199" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93201" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93203" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93209" do
    title "Windows Server 2019 manually managed application account passwords must be changed at least every 60 days and when a system administrator with knowledge of the password leaves the organization."
    desc  "Setting application account passwords to expire may cause applications to stop functioning. However, not changing them on a regular basis exposes them to attack. If managed service accounts are used, this alleviates the need to manually change application account passwords."
    desc  'check', "Determine if manually managed application/service accounts exist. If none exist, this is NA.
      If passwords for manually managed application/service accounts are not changed at least every 60 days and when an administrator with knowledge of the password leaves the organization, this is a finding.
      Identify manually managed application/service accounts.
      To determine the date a password was last changed:
  
      Domain controllers:
      Open \"PowerShell\".
      Enter \"Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet\", where [application account name] is the name of the manually managed application/service account.
      If the \"PasswordLastSet\" date is more than 60 days old, this is a finding.
  
      Member servers and standalone systems:
      Open \"Command Prompt\".
      Enter 'Net User [application account name] | Find /i \"Password Last Set\"', where [application account name] is the name of the manually managed application/service account.
      If the \"Password Last Set\" date is more than 60 days old, this is a finding."
    desc  'fix', "Change passwords for manually managed application/service accounts at least every 60 days and when an administrator with knowledge of the password leaves the organization.
      It is recommended that system-managed service accounts be used whenever possible."
  end

  control "V-93285" do
    title "Windows Server 2019 maximum age for machine account passwords must be configured to 60 days or less."
    desc  "Computer account passwords are changed automatically on a regular basis. This setting controls the maximum password age that a machine account may have. This must be set to no more than 60 days, ensuring the machine changes its password bi-monthly."
    desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

      Value Name: MaximumPasswordAge

      Value Type: REG_DWORD
      Value: 0x0000001e (60) (or less, but not 0)"
    desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Domain member: Maximum machine account password age\" to \"60\" or less (excluding \"0\", which is unacceptable)."
  end
  
  control "V-93313" do
    desc  "fix", "Ensure Exploit Protection system-level mitigation, \"Data Execution Prevention (DEP)\", is turned on.  The default configuration in Exploit Protection is \"On by default\" which meets this requirement.

    Open \"Windows Defender Security Center\".
    Select \"App & browser control\".
    Select \"Exploit protection settings\".
    Under \"System settings\", configure \"Data Execution Prevention (DEP)\" to \"On by default\" or \"Use default (<On>)\"."
  end

  control "V-93315" do
    desc  "fix", "Ensure Exploit Protection system-level mitigation, \"Control flow guard (CFG)\", is turned on. The default configuration in Exploit Protection is \"On by default\" which meets this requirement.

    Open \"Windows Defender Security Center\".
    Select \"App & browser control\".
    Select \"Exploit protection settings\".
    Under \"System settings\", configure \"Control flow guard (CFG)\" to \"On by default\" or \"Use default (<On>)\"."
  end

  control "V-93317" do
    desc  "fix", "Ensure Exploit Protection system-level mitigation, \"Validate exception chains (SEHOP)\", is turned on. The default configuration in Exploit Protection is \"On by default\" which meets this requirement.

    Open \"Windows Defender Security Center\".
    Select \"App & browser control\".
    Select \"Exploit protection settings\".
    Under \"System settings\", configure \"Validate exception chains (SEHOP)\" to \"On by default\" or \"Use default (<On>)\"."
  end

  control "V-93319" do
    desc  "fix", "Ensure Exploit Protection system-level mitigation, \"Validate heap integrity\" is turned on. The default configuration in Exploit Protection is \"On by default\" which meets this requirement.

    Open \"Windows Defender Security Center\".
    Select \"App & browser control\".
    Select \"Exploit protection settings\".
    Under \"System settings\", configure \"Validate heap integrity\" to \"On by default\" or \"Use default (<On>)\"."
  end

  control "V-93321" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for Acrobat.exe:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93323" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for AcroRd32.exe:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93325" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for chrome.exe:

    DEP:
    Enable: ON"
  end

  control "V-93327" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for EXCEL.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93329" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for firefox.exe:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON"
  end

  control "V-93331" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for FLTLDR.EXE:

    DEP:
    Enable: ON

    ImageLoad:
    BlockRemoteImageLoads: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON

    Child Process:
    DisallowChildProcessCreation: ON"
  end

  control "V-93333" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for GROOVE.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    ImageLoad:
    BlockRemoteImageLoads: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON

    Child Process:
    DisallowChildProcessCreation: ON"
  end

  control "V-93335" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for iexplore.exe:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93337" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for INFOPATH.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93339" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for java.exe, javaw.exe, and javaws.exe:

    DEP:
    Enable: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93341" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for lync.exe:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93343" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for MSACCESS.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93345" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for MSPUB.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93347" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for OIS.EXE:

    DEP:
    Enable: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93349" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for OneDrive.exe:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    ImageLoad:
    BlockRemoteImageLoads: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93351" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for OUTLOOK.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93353" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for plugin-container.exe:

    DEP:
    Enable: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93355" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for POWERPNT.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93357" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for PPTVIEW.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93359" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for VISIO.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93361" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for VPREVIEW.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93363" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for WINWORD.EXE:

    DEP:
    Enable: ON

    ASLR:
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93365" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for wmplayer.exe:

    DEP:
    Enable: ON

    Payload:
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93367" do
    desc  "fix", "Ensure the following mitigations are turned \"ON\" for wordpad.exe:

    DEP:
    Enable: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON"
  end

  control "V-93379" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not mandatory  for this security categorization in CMS ARS 3.1"
  end

  control "V-93425" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93427" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93429" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93431" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93433" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93435" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93453" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93455" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93457" do
    desc  "check", "Open \"Windows PowerShell\".

    Domain Controllers:
    Enter \"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 60.00:00:00\"
    This will return accounts that have not been logged on to for 60 days, along with various attributes such as the Enabled status and LastLogonDate.

    Member servers and standalone systems:
    Copy or enter the lines below to the PowerShell window and enter. (Entering twice may be required. Do not include the quotes at the beginning and end of the query.)
    \"([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
    $user = ([ADSI]$_.Path)
    $lastLogin = $user.Properties.LastLogin.Value
    $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
    if ($lastLogin -eq $null) {
    $lastLogin = 'Never'
    }
    Write-Host $user.Name $lastLogin $enabled
    }\"
    This will return a list of local accounts with the account name, last logon, and if the account is enabled (True/False).
    For example: User1 10/31/2015 5:49:56 AM True
    Review the list of accounts returned by the above queries to determine the finding validity for each account reported.

    Exclude the following accounts:
    - Built-in administrator account (Renamed, SID ending in 500)
    - Built-in guest account (Renamed, Disabled, SID ending in 501)
    - Application accounts

    If any enabled accounts have not been logged on to within the past 60 days, this is a finding.

    Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO."
    desc  "fix", "Regularly review accounts to determine if they are still active. Remove or disable accounts that have not been used in the last 60 days."
  end

  control "V-93463" do
    title "Windows Server 2019 minimum password length must be configured to 15 characters."
    desc  "check", "Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".
      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
      If the value for the \"Minimum password length,\" is less than \"15\" characters, this is a finding.

      For server core installations, run the following command:
      Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
      If \"MinimumPasswordLength\" is less than \"15\" in the file, this is a finding."
    desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Minimum password length\" to \"15\" characters."
  end

  control "V-93479" do
    title "Windows Server 2019 password history must be configured to 6 passwords remembered."
    desc  "A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is \"6\" for Windows domain systems. CMS has decided this is the appropriate value for all Windows systems."
    desc  "check", "Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".
      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
      If the value for \"Enforce password history\" is less than \"6\" passwords remembered, this is a finding.

      For server core installations, run the following command:
      Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
      If \"PasswordHistorySize\" is less than \"6\" in the file, this is a finding."
    desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Enforce password history\" to \"6\" passwords remembered."
  end

  control "V-93483" do
    title "Windows Server 2019 domain Controller PKI certificates must be issued by the CMS PKI or an approved External Certificate Authority (ECA)."
    desc  "check", "This applies to domain controllers. It is NA for other systems.
      Run \"MMC\".
      Select \"Add/Remove Snap-in\" from the \"File\" menu.
      Select \"Certificates\" in the left pane and click the \"Add >\" button.
      Select \"Computer Account\" and click \"Next\".
      Select the appropriate option for \"Select the computer you want this snap-in to manage\" and click \"Finish\".
      Click \"OK\".
      Select and expand the Certificates (Local Computer) entry in the left pane.
      Select and expand the Personal entry in the left pane.
      Select the Certificates entry in the left pane. In the right pane, examine the \"Issued By\" field for the certificate to determine the issuing CA.
      If the \"Issued By\" field of the PKI certificate being used by the domain controller does not indicate the issuing CA is part of the CMS PKI or an approved ECA, this is a finding.
      If the certificates in use are issued by a CA authorized by the Component's CIO, this is a CAT II finding."
    desc  "fix", "Obtain a server certificate for the domain controller issued by the CMS PKI or an approved ECA."

    describe "For this CMS ARS 3.1 overlay, this control must be reviewed manually" do 
      skip "For this CMS ARS 3.1 overlay, this control must be reviewed manually"
    end
  end

  control "V-93485" do
    title "Windows Server 2019 PKI certificates associated with user accounts must be issued by a CMS PKI or an approved External Certificate Authority (ECA)."

    describe "For this CMS ARS 3.1 overlay, this control must be reviewed manually" do 
      skip "For this CMS ARS 3.1 overlay, this control must be reviewed manually"
    end
  end

  control "V-93487" do
    title "Windows Server 2019 must have the CMS Root Certificate Authority (CA) certificates installed in the Trusted Root Store."
    desc  "To ensure secure CMS websites and CMS-signed code are properly validated, the system must trust the CMS Root CAs. The CMS root certificates will ensure that the trust chain is established for server certificates issued from the CMS CAs."
    desc  "check", "Verify the CMS Root CA certificates are installed in the Trusted Root Store."
    desc  "fix", "Install the CMS Root CA certificates."
  
    describe "For this CMS ARS 3.1 overlay, this control must be reviewed manually" do 
      skip "For this CMS ARS 3.1 overlay, this control must be reviewed manually"
    end
  end
  
  control "V-93489" do
    title "Windows Server 2019 must have the CMS Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems."
    desc  "To ensure users do not experience denial of service when performing certificate-based authentication to CMS websites due to the system chaining to a root other than CMS Root CAs, the CMS Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems."
    desc  "check", "This is applicable to unclassified systems. It is NA for others.
    Verify that the CMS Interoperability Root Certificate Authority (CA) cross-certificates is installed in the Untrusted Certificates Store on unclassified systems."
    desc  "fix", "Install the CMS Interoperability Root CA cross-certificates on unclassified systems."
    
    describe "For this CMS ARS 3.1 overlay, this control must be reviewed manually" do 
      skip "For this CMS ARS 3.1 overlay, this control must be reviewed manually"
    end
  end

  control "V-93491" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the CCEB is not applicable to CMS"
  end

  control "V-93499" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not mandatory in CMS ARS 3.1"
  end

  control "V-93501" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not mandatory in CMS ARS 3.1"
  end

  control 'V-93509' do
    title 'Windows Server 2019 directory service must be configured to terminate LDAP-based network connections to the directory server after thirty minutes of inactivity.'
    desc  'check', 'This applies to domain controllers. It is NA for other systems.
    Open an elevated \"Command Prompt\" (run as administrator).
    Enter \"ntdsutil\".
    At the \"ntdsutil:\" prompt, enter \"LDAP policies\".
    At the \"ldap policy:\" prompt, enter \"connections\".
    At the \"server connections:\" prompt, enter \"connect to server [host-name]\"
    (where [host-name] is the computer name of the domain controller).
    At the \"server connections:\" prompt, enter \"q\".
    At the \"ldap policy:\" prompt, enter \"show values\".
    If the value for MaxConnIdleTime is greater than \"1800\" (30 minutes) or is not specified, this is a finding.
    Enter \"q\" at the \"ldap policy:\" and \"ntdsutil:\" prompts to exit.

    Alternately, Dsquery can be used to display MaxConnIdleTime:
    Open \"Command Prompt (Admin)\".
    Enter the following command (on a single line).
    dsquery * \"cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,dc=[forest-name]\" -attr LDAPAdminLimits

    The quotes are required and dc=[forest-name] is the fully qualified LDAP name of the domain being reviewed (e.g., dc=disaost,dc=mil).
    If the results do not specify a \"MaxConnIdleTime\" or it has a value greater than \"1800\" (30 minutes), this is a finding.'
    desc  'fix', 'Configure the directory service to terminate LDAP-based network connections to the directory server after 30 minutes of inactivity.
    Open an elevated \"Command prompt\" (run as administrator).
    Enter \"ntdsutil\".
    At the \"ntdsutil:\" prompt, enter \"LDAP policies\".
    At the \"ldap policy:\" prompt, enter \"connections\".
    At the \"server connections:\" prompt, enter \"connect to server [host-name]\" (where [host-name] is the computer name of the domain controller).
    At the \"server connections:\" prompt, enter \"q\".
    At the \"ldap policy:\" prompt, enter \"Set MaxConnIdleTime to 1800\".
    Enter \"Commit Changes\" to save.
    Enter \"Show values\" to verify changes.
    Enter \"q\" at the \"ldap policy:\" and \"ntdsutil:\" prompts to exit.'
  end

  control "V-93517" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1 for this system categorization"
  end

  control "V-93519" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1 for this system categorization"
  end

  control "V-93521" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1 for this system categorization"
  end

  control "V-93523" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1 for this system categorization"
  end

  control "V-93525" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1 for this system categorization"
  end

  control "V-93527" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1 for this system categorization"
  end

  control "V-93529" do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1 for this system categorization"
  end

  control "V-93543" do
    impact 0.0
    desc "caveat", "This is Not Applicable since the related security control is not included in CMS ARS 3.1"
  end

  control "V-93565" do
    desc  "fix", "Ensure Exploit Protection system-level mitigation, \"Randomize memory allocations (Bottom-Up ASLR)\" is turned on. The default configuration in Exploit Protection is \"On by default\" which meets this requirement.
      Open \"Windows Defender Security Center\".
      Select \"App & browser control\".
      Select \"Exploit protection settings\".
      Under \"System settings\", configure \"Randomize memory allocations
      (Bottom-Up ASLR)\" to \"On by default\" or \"Use default (<On>)\"."
  end

  control "V-93567" do
    title "Windows Server 2019 must employ automated mechanisms to determine the state of system components with regard to flaw remediation every 72 hours."
    desc  "Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws."
    desc  "check", "Verify the operating system employs automated mechanisms to determine the state of system components with regard to flaw remediation no less often than once every seventy-two (72) hours. If it does not, this is a finding."
    desc  "fix", "Configure the operating system to employ automated mechanisms to determine the state of system components with regard to flaw remediation no less often than once every seventy-two (72) hours."

    describe "A manual review is required to verify the operating system employs automated mechanisms to determine the state of system components with regard to flaw remediation no less often than once every seventy-two (72) hours. If it does not, this is a finding." do	
      skip "A manual review is required to verify the operating system employs automated mechanisms to determine the state of system components with regard to flaw remediation no less often than once every seventy-two (72) hours. If it does not, this is a finding."	
    end
  end

  end