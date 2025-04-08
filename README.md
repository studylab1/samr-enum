# samr-enum

`samr-enum.py` is a Python script that leverages the Microsoft SAMR protocol to enumerate domain users, groups, computers, password policies, and other account-related information from a target system. It supports both **NTLM** (default) and **Kerberos** authentication and can optionally export results in multiple formats (TXT, CSV, JSON).

The tool was initially developed as part of a Master’s thesis in cybersecurity. If you would like to explore the original commit history, the comprehensive research data, and lab-based demonstration materials, please see the [SAMR-Enum-Lab](https://github.com/studylab1/SAMR-Enum-Lab/)  repository. That repository includes traffic captures, detailed analysis, and extensive documentation of how samr-enum evolved over time.

### Notable Features

- Enumerate domain users, local (alias) groups, domain groups, and more.
- Display detailed debug output for SAMR calls.
- Securely prompt for a password if none is provided.
- Export enumeration results in multiple formats (TXT, CSV, JSON).
- Supports NTLM (default) and Kerberos authentication.
- Cross-forest enumeration.

### Requirements

- **Python**: 3.x
- **Dependencies**:
  - `Impacket` 0.12 (MIT License)  
    *Note: Some antivirus solutions (e.g., Microsoft Defender, CrowdStrike) may flag Impacket components.*
  - Linux-Specific Packages (required if running on Linux):  
     - python3-dev (or your distribution’s equivalent, e.g. python3.12-dev)
     - libkrb5-dev  
These packages provide the necessary C headers and libraries for compiling parts of Impacket (and its dependencies like pyasn1 and gssapi) to support encryption and Kerberos functionality.
- **Platform**: Windows or Linux systems with access to a configured Active Directory.


### Installation

1. **Clone the Repository (Full Project)**

   ```bash
   git clone https://github.com/studylab1/samr-enum.git
   cd samr-enum
   ```

2. **Install Dependencies**
```bash
pip install impacket==0.12
```

### Usage

The tool contains a single Python file (samr-enum.py). Execute the tool from the command line:
```bash
python samr-enum.py [options]
 ```
   
   For detailed options:
```bash
python samr-enum.py help
```

#### Required OPTIONS

- **target:**  The remote system (IP address or hostname) to connect to.
- **username:**  The username used for authentication.
- **password:**  The password for authentication. If left empty (e.g., `password=`), the tool securely prompts for it.
- **enumerate:**  The enumeration type (e.g., `users`, `computers`, `local-groups`, `domain-groups`, `account-details`, `summary`, etc.).

#### Optional OPTIONS

- **domain:** The domain of the user for authentication (required if using Kerberos).
- **auth:**  The authentication protocol. Can be ntlm (default) or kerberos.
- **debug:**  Display debug details of the SAMR calls.
- **export and format:**  Export the data in txt, csv, or json format. Default is txt.
- **opnums:**  Display SAMR OpNums in the output.
- **help:**  Print the help page and exit.
- **acl**  Query and display the Access Control List (ACL) for the target object (only for `enumerate=account-details` supported)

#### Enumeration Parameters (use with enumerate=)

- **users:** List all user accounts.
- **computers:** List all computer accounts.
- **local-groups:** List all local (alias) groups.
- **domain-groups:** List all domain groups.
- **user-memberships-localgroups:** Show local group memberships for a specified user (requires user=<USERNAME>).
- **user-memberships-domaingroups:** Show domain group memberships for a specified user (requires user=<USERNAME>).
- **account-details:** Display account details for a specific user (by username or RID; use user=<USERNAME/RID>).
- **local-group-details:** Display details for a specific local group (use group=<GROUP>).
- **domain-group-details:** Display details for a specific domain group (use group=<GROUP>).
- **display-info:** List all objects with descriptive fields (use type=<users|computers|local-groups|domain-groups>).
- **summary:** Display a summary report for the domain (includes domain SID, user count, group counts, password policy, etc.).

###  Parameters Example
```
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=users
  python samr-enum.py target=192.168.1.1 username=micky password=  enumerate=computers debug
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=local-groups export=export.csv format=csv
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=domain-groups opnums
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=user-memberships-localgroups user=Administrator
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=user-memberships-domaingroups user=Administrator
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=account-details user=Administrator acl
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=local-group-details group="Administrators"
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=domain-group-details group="Domain Admins"
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=users
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=computers
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=local-groups
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=domain-groups
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=summary auth=kerberos domain=domain-y.local
  python samr-enum.py help
```
###  Output Example

```
$ python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=account-details user=Administrator

Execution started at: 2025-03-08 17:40:35.104369

Account Details for Administrator:
  RID:                  500
  Username:             Administrator
  Full Name:            Display name
  Description:          Built-in account for administering the computer/domain
  Last Logon:           2025-03-08 13:37:57
  Logon Count:          68
  Password Last Set:    2025-02-02 15:42:23
  Password Can Chg:     2025-02-03 15:42:23
  Password Force Chg:   Never
  Password Expired:     No
  Password Never Exp-s: No
  Password Bad Count:   0
  Account Expires:      Never
  Account Disabled:     No
  Pre-Auth. Required:   Yes
  Delegation Allowed:   Yes
  Smartcard Required:   No

  Primary Group ID:     513
  Home Directory:       C:\temp
  Home Drive:           
  Profile Path:         profile path
  Script Path:          logon script
  Workstations:         
================================================================
Execution time:     	0.16 seconds
Destination target: 	ydc1.domain-y.local
Domain SID:         	S-1-5-21-3461051276-3658573231-1749369878
Account:            	enum-x
Enumerate:          	account-details
Authentication:     	NTLM
Execution status:   	success
Number of objects:  	1
OpNums called:
  Name                              OpNum  Access Mask
-------------------------------------------------------
  SamrConnect                       0     0x00000031
  SamrEnumerateDomainsInSamServer   6     --
  SamrLookupDomainInSamServer       5     --
  SamrOpenDomain                    7     0x00000301
  SamrLookupNamesInDomain           17    --
  SamrLookupNamesInDomain           17    --
  SamrOpenUser                      34    0x0002011B
  SamrQueryInformationUser2         47    --
  SamrCloseHandle                   1     --
  SamrCloseHandle                   1     --
================================================================
```

```
$ python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! enumerate=display-info type=users

Execution started at: 2025-03-12 22:34:42.314859

RID      Last Logon   PwdSet     PwdNE      PwdExp     ForceChg   AccDis     PreAuth    Delg     BadCnt     Username        Full Name            
-------------------------------------------------------------------------------------------------------------------------------------------------
500      2025.03.08   2025.02.02 No         No         Never      No         Yes        Yes      0          Administrator   Display name        
501      Never        Never      Yes        No         Never      Yes        Yes        Yes      0          Guest                               
502      Never        2024.11.01 No         No         Never      Yes        Yes        Yes      0          krbtgt                              
1105     2025.02.02   2024.11.01 Yes        No         Never      No         Yes        Yes      0          enum            Domain Enum         
1119     2025.01.24   2024.11.01 No         No         Never      No         Yes        Yes      0          enum_a          enum                
1120     Never        2024.11.02 No         No         Never      No         Yes        Yes      0          ANTONE_PICKETT  ANTONE_PICKETT      
1121     Never        2024.11.02 No         No         Never      No         Yes        Yes      0          MICHEL_OSBORNE  MICHEL_OSBORNE      
1122     Never        2024.11.02 No         No         Never      No         Yes        Yes      0          CARL_ANDREWS    CARL_ANDREWS        
1123     Never        2024.11.02 No         No         Never      No         Yes        Yes      0          LORIE_CHASE     LORIE_CHASE         
1124     Never        2024.11.02 No         No         Never      No         Yes        Yes      0          DICK_CRAFT      DICK_CRAFT          
1125     Never        2024.11.02 No         No         Never      No         Yes        Yes      0          MANUELA_SANDERS MANUELA_SANDERS
......
-------------------------------------------------------------------------------------------------------------------------------------------------
RID      Last Logon   PwdSet     PwdNE      PwdExp     ForceChg   AccDis     PreAuth    Delg     BadCnt     Username        Full Name            

================================================================
Execution time:     	5.28 seconds
Destination target: 	ydc1.domain-y.local
Domain SID:         	S-1-5-21-3461051276-3658573231-1749369878
Account:            	enum-x
Enumerate:          	display-info
Authentication:     	NTLM
Execution status:   	success
Number of objects:  	497
================================================================
```

```
$ python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! enumerate=summary
Execution started at: 2025-03-12 22:33:46.027930

Domain Information:
  Domain SID:                  S-1-5-21-3461051276-3658573231-1749369878
  Domain Name:                 DOMAIN-Y
  UAS Compatible:              No

Account Lockout Settings:
  Lockout Threshold:           0
  Lockout Duration (days):     0
  Lockout Window (days):       0
  Force Logoff (days):         0

Password Policy:
  Minimum Password Length:     N/A
  Minimum Password Age (days): 1
  Maximum Password Age (days): 0
  Password History Length:     N/A
  Password Properties:
    PwdComplex                 Yes
    NoAnon                     No
    NoClrChg                   No
    LockAdmins                 No
    StoreClr                   No
    RefuseChg                  No

Total Users:                   497
Total Computers:               12
Total Domain Groups:           114
Total Local Groups:            28

================================================================
Execution time:     	0.35 seconds
Destination target: 	ydc1.domain-y.local
Domain SID:         	S-1-5-21-3461051276-3658573231-1749369878
Account:            	enum-x
Enumerate:          	summary
Authentication:     	NTLM
Execution status:   	success
Number of objects:  	1
================================================================
```

```
$ python samr-enum.py target=ydc1.domain-y.local username=Administrator password=LabAdm1! enumerate=account-details user=Administrator acl
Execution started at: 2025-04-08 01:02:12.128610

Account Details for Administrator:
  RID:                  500
  Username:             Administrator
  Full Name:            Display name
  Description:          Built-in account for administering the computer/domain
  Last Logon:           2025-04-06 10:56:41
  Logon Count:          72
  Password Last Set:    2025-02-02 15:42:23
  Password Can Chg:     2025-02-03 15:42:23
  Password Force Chg:   Never
  Password Expired:     No
  Password Never Exp-s: No
  Password Bad Count:   0
  Account Expires:      Never
  Account Disabled:     No
  Pre-Auth. Required:   Yes
  Delegation Allowed:   Yes
  Smartcard Required:   No

  Primary Group ID:     513
  Home Directory:       C:\temp
  Home Drive:           
  Profile Path:         profile path
  Script Path:          logon script
  Workstations:         
  ACL:
    Owner SID:	S-1-5-32-544 (Administrators)
    Group SID:	S-1-5-32-544 (Administrators)

    Control Flags:
		OWND  GRPD  DPRS  DACD  SPRS  SACD  DAIR  SAIR  DAIN  SAIN  DPRT  SPRT  RMCV  SELF
		----------------------------------------------------------------------------------
		No    No    Yes   No    No    No    No    No    No    No    No    No    No    Yes 

    DACL ACEs:
	  ACE 1:
		Type:		Access Allowed
		NT ACE Flags:	0x00
		Access Mask:	0x0002035B (USR_READ_GEN, USR_READ_PREF, USR_CHG_PW, USR_FORCE_PW, USR_READ_ACC, USR_CREATE, USR_DELETE, GEN_READ)
		SID:		S-1-1-0
	  ACE 2:
		Type:		Access Allowed
		NT ACE Flags:	0x00
		Access Mask:	0x000F07FF (USR_READ_GEN, USR_READ_PREF, USR_READ_LOGON, USR_CHG_PW, USR_FORCE_PW, USR_LIST_GRPS, USR_READ_ACC, USR_WR_ACC, USR_CREATE, USR_DELETE, USR_AUTO_LOCK, GEN_READ, GEN_WRITE, GEN_EXEC)
		SID:		S-1-5-32-544
	  ACE 3:
		Type:		Access Allowed
		NT ACE Flags:	0x00
		Access Mask:	0x0002031B (USR_READ_GEN, USR_READ_PREF, USR_CHG_PW, USR_FORCE_PW, USR_CREATE, USR_DELETE, GEN_READ)
		SID:		S-1-15-3-1024-1730716382-2949791265-2036182297-688374192-553408039-4133924312-4201181712-267922143
	  ACE 4:
		Type:		Access Allowed
		NT ACE Flags:	0x00
		Access Mask:	0x00020044 (USR_READ_LOGON, USR_READ_ACC, GEN_READ)
		SID:		S-1-5-21-3461051276-3658573231-1749369878-500
================================================================
Execution time:     	0.05 seconds
Destination target: 	ydc1.domain-y.local
Domain SID:         	S-1-5-21-3461051276-3658573231-1749369878
Account:            	Administrator
Enumerate:          	account-details
Authentication:     	NTLM
Execution status:   	success
Number of objects:  	1
================================================================
```

### Configuration & Troubleshooting
- Ensure your Python environment meets the specified version and dependency requirements.
- If you experience issues with antivirus software (e.g., Microsoft Defender, CrowdStrike, or other AV solutions), consider adjusting your AV settings, as Impacket components may be flagged.

## Contributing

Contributions are welcome! Please adhere to PEP 8 styling and include appropriate PEP 257 docstrings in your code. Fork the repository, implement your changes, and submit a pull request.

## License

- This project is licensed under the MIT License. See the LICENSE file for details.
- Impacket is licensed under a modified version of the Apache License 2.0. See the NOTICE file for more details.

## Disclaimer
This tool is provided for legitimate security testing, research, or educational purposes only. Ensure that you have proper authorization before enumerating Active Directory systems.

## Versioning

This project uses [Semantic Versioning](https://semver.org/) (SemVer) to track releases. The current version is defined in the `samr-enum.py` file as follows:

```python
__version__ = "1.2.0"
```

## Acknowledgements

This project makes use of [Impacket](https://github.com/fortra/impacket), a library that provides essential implementations for SMB and various RPC protocols. Impacket is distributed under a modified version of the Apache License 2.0. While it largely follows the standard Apache 2.0 terms, please review the [Impacket LICENSE file](https://github.com/fortra/impacket/blob/master/LICENSE) for the exact terms and any modifications that apply.

Sincere thanks are extended to the developers and contributors of Impacket for their outstanding work.
