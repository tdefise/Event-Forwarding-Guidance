# Event Forwarding Guidance

This repository hosts content for aiding administrators in collecting security relevant Windows event logs using Windows Event Forwarding (WEF). This repository is a companion to [Spotting the Adversary with Windows Event Log Monitoring](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf) paper. The list of events in this repository are more up to date than those in the paper.

The repository contains:

* [Recommended Windows events](./Events/) to collect. Regardless of using WEF or a third party SIEM, the list of recommended events should be useful as a starting point for what to collect. The list of events in this repository are more up to date than those in the paper.
* [Scripts](./scripts/) to create custom Event Log views and create WEF subscriptions.
* [WEF subscriptions](./Subscriptions/) in XML format.

## Changelog from Official
* Added Event IDs that have been added within the security updates of August 11, 2020 due to CVE-2020-1472, Netlogon Elevation of Privilege Vulnerability
* Added Event ID 4697, as recommended to detect MITTRE ATT&CK Technique [T1543.003 - Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/).<BR>
Security Monitoring recommendation are available from [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697#security-monitoring-recommendations)
* Added Event ID 4768, as recommended to detect MITTRE ATT&CK Technique [T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/).<BR>
Security Monitoring recommendation are available from [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768#security-monitoring-recommendations)
* Added Event ID 4738(S) & 4670(S) as recommended to detect MITTRE ATT&CK Technique [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/).<BR>
Security Monitoring recommendation are available from [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738)
* Added Event ID 4724 as recommended by [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724#security-monitoring-recommendations)
* Added Event ID 
* 
#### Tips

Here below are some tips that can either help you to:
- Prevent **directly** threats
- Increase your visibility

The example are some tools that are free.
Some of them can be bypass, but even if it will be bypass, the attacker will:
- Have to see that's it is there
- Search a way to bypass it
- It will create logs that can be correlated with all the events you already gathered.
- It will generate noise by the attackers.

##### AppLocker

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) helps you control which apps and files users can run. These include executable files, scripts, Windows Installer files, dynamic-link libraries (DLLs), packaged apps, and packaged app installers.

When AppLocker policy enforcement is set to **Enforce rules**, rules are enforced for the rule collection and all events are audited.<br>
When AppLocker policy enforcement is set to **Audit only**, rules are only evaluated but all events generated from that evaluation are written to the AppLocker log. 

I would recommend to setup at least the audit log on your critical assets.

##### Sysmon

If you don't have an EDR (Endpoint Protection & Responce) that provides you more visibility on endpoint for detection and response, I would recomment to have a look at [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

Sysmon is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time. By collecting the events it generates using Windows Event Collection or SIEM agents and subsequently analyzing them, you can identify malicious or anomalous activity and understand how intruders and malware operate on your network.

Here are some configurations you can use as an example:
- [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)- [ionstrom](https://github.com/ion-storm)

Note that it is pretty common to see Sigma rules that leverage Sysmon logs, and it there are a lot of resources for well used security solutions such as [QRadar](https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.extensions.doc/r_sysmon_setup.html), [Splunk](https://splunkbase.splunk.com/app/1914/), Azure Sentinel, ... 

## Links

* [Microsoft Windows Event Forwarding resources](https://aka.ms/wef)
* [Use Windows Event Forwarding to help with intrusion detection](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
* [Windows 10 and Windows Server 2016 security auditing and monitoring reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630)
* [Microsoft's Threat Protection: Advanced security audit policy settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
* [Microsoft's Threat Protection: Security auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
* [List of important events from Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
* [Microsoft SysInternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [ACSC GitHub Windows Event Logging repository](https://github.com/AustralianCyberSecurityCentre/windows_event_logging)
* [ACSC Windows Event Logging Technical Guidance](https://acsc.gov.au/publications/protect/Windows_Event_Logging_Technical_Guidance.pdf)
* [Creating Custom Windows Event Forwarding Logs](https://blogs.technet.microsoft.com/russellt/2016/05/18/creating-custom-windows-event-forwarding-logs/)
* [Introducing Project Sauron](https://blogs.technet.microsoft.com/russellt/2017/05/09/project-sauron-introduction/)
* [Project Sauron GitHub repository](https://github.com/russelltomkins/project-sauron)
* [Windows Event Forwarding for Network Defense](https://medium.com/palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)
* [Palantir Windows Event Forwarding GitHub repository](https://github.com/palantir/windows-event-forwarding)

## License

See [LICENSE](./LICENSE.md).

## Disclaimer

See [DISCLAIMER](./DISCLAIMER.md).
