#!/usr/bin/env python3
"""
samr-enum.py - A SAMR Enumeration Script using Impacket.
Copyright (c) 2025. Licensed under the MIT License.

This Python tool leverages the Microsoft SAMR protocol to enumerate domain
users, groups, computers, password policies, and other account-related information
from a target system. It supports both NTLM (default) and Kerberos authentication,
and can optionally export results in various formats (TXT, CSV, JSON).
Special thanks to the developers of Impacket (https://github.com/fortra/impacket) for providing the underlying library used in this project.

Features:
  - Enumerate domain users, local groups, domain groups, and more.
  - Display detailed debug output for SAMR calls.
  - Securely prompt for a password if none is provided.
  - Export enumeration results in multiple formats.
  - Supports NTLM (default) and Kerberos authentication.
"""

__version__ = "1.0.1"

# Global help text constant
HELP_TEXT = r"""
SAMR Enumeration Script - Help

Usage:
    samr-enum.py <OPTIONS> <ENUMERATION PARAMETER> [ENUMERATION PARAMETER OPTIONS]

Required OPTIONS:
  target            Target system (IP address or hostname).
  username          Username used for authentication on the remote server.
  password          Password for authentication. If empty (i.e., password=), the tool will securely prompt for it.
  enumerate         The enumeration type. See the ENUMERATION PARAMETERS section below.

Optional OPTIONS:
  domain            Domain of the user for authentication (required if using Kerberos).
  auth              Authentication protocol. Acceptable values: 'ntlm' (default) or 'kerberos'.
  debug             Display debug details of the SAMR calls. Acceptable values: 'true' or 'false' (default: 'false').
  export            Export the data. Acceptable values: 'txt' (default), 'csv', or 'json'.
    format          Acceptable values are 'txt', 'csv' or 'json', with the default being 'txt'.
  opnums            Set to 'true' to display SAMR OpNums in output (default: 'false').
  help              Print help page.

ENUMERATION PARAMETERS:
  The following parameters control what to enumerate. Provide one of these (omitting the "enumerate=" prefix)
  along with any required options:

    users
         List all user accounts.

    computers
         List all computer accounts.

    local-groups
         List all local groups.

    domain-groups
         List all domain groups.

    user-memberships-localgroups
         List all local groups that a user is a member of. (Parameter option: user)

    user-memberships-domaingroups
         List all domain groups that a user is a member of. (Parameter option: user)

    account-details user=<USERNAME/RID>
         Display account details for a specific user (by username or RID). (Parameter option: user)

    local-group-details group=<GROUP>
         Display local/builtin group details. (Parameter option: group)

    domain-group-details group=<GROUP>
         Display domain group details. (Parameter option: group)

    display-info
         List all objects with additional descriptive fields. (Parameter option: 'type' with values 'users', 'computers', 'local-groups', 'domain-groups')

    account-details user=<USERNAME/RID>
         Display account details for a specific user (by username or RID). (Parameter option: user)

    summary
        Display a summary report for the domain. The summary includes:
           - Domain Information (name, SID, etc.)
           - Total number of user accounts
           - Total number of computer accounts
           - Total number of domain groups
           - Total number of local groups (aliases)
           - Password policy details
           - Lockout policy details

Usage Examples:
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=users
  python samr-enum.py target=192.168.1.1 username=micky password=  enumerate=computers debug=true
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=local-groups export=export.csv format=csv
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=domain-groups opnums=true
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=user-memberships-localgroups user=Administrator
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=user-memberships-domaingroups user=Administrator
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=account-details user=Administrator
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=local-group-details group="Administrators"
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=domain-group-details group="Domain Admins"
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=users
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=computers
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=local-groups
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=display-info type=domain-groups
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=summary auth=kerberos domain=domain-y.local
  python samr-enum.py help

For help, run:
    samr-enum.py help

Column Abbreviations for "display-info type=users" output:
  - RID:          Relative Identifier.
  - Last Logon:   Date of last logon (YYYY.MM.DD).
  - PwdSet:       Date when the password was set (YYYY.MM.DD).
  - PwdNE:        "Password Never Expires" flag (Yes/No).
  - PwdExp:       "Password Expired" flag (Yes/No).
  - ForceChg:     Date when a password force-change is scheduled (YYYY.MM.DD).
  - AccDis:       "Account Disabled" flag (Yes/No).
  - PreAuth:      "Pre-Authentication required" flag (Yes/No).
  - Delg:         "Delegation required" flag (Yes/No).
  - BadCnt:       Count of bad password attempts.
  - Username:     The user's login name.
  - Full Name:    The user's full display name.

Column Abbreviations for "display-info type=computers" output:
  - RID:          Relative Identifier.
  - Name:         Computer name (the network name of the machine, shown without its trailing ‘$’ sign).
  - Logons:       Count of successful logons.
  - LastLogon:    Date of last logon (YYYY.MM.DD).
  - PwdLastSet:   Date when the computer’s password was last set (YYYY.MM.DD).
  - BadPwdCnt:    Count of bad password attempts.
  - PID:          Primary Group ID associated with the computer account.
  - Type:         Trust relationship type (indicates whether the computer is registered as a workstation or server).
  - Enabled:      “Yes” if the account is active; “No” if disabled.
  - PwdNReq:      “Password Not Required” flag (Yes/No).
  - PwdNExp:      “Password Never Expires” flag (Yes/No).
  - Deleg:        Delegation status flag (Yes/No).
  - AcctStatus:   Account status/type (e.g. “Enabled” or “Disabled”).
  - Description:  Description field containing additional information or notes.

Summary Output Fields (when using enumerate=summary):
  Domain SID:                The security identifier (SID) of the domain.
  Domain Name:               The NetBIOS or DNS name of the domain.
  UAS Compatible:            Indicates whether User Account System (UAS) compatibility is required.
  Lockout Threshold:         The number of failed logon attempts before account lockout.
  Lockout Duration:          The duration (in days) that an account remains locked out.
  Lockout Observation Window:The time window (in days) during which failed logon attempts are counted.
  Force Logoff:              The maximum logoff time (in days) enforced by the domain.
  Minimum Password Length:   The minimum number of characters required for passwords.
  Minimum Password Age:      The minimum number of days a password must be used before it can be changed.
  Maximum Password Age:      The maximum number of days a password remains valid.
  Password History Length:   The number of previous passwords stored to prevent reuse.
  Password Properties:       A list of password requirements (e.g., complexity, no anonymous changes).
  Total Users:               The total number of user accounts in the domain.
  Total Domain Groups:       The total number of domain groups.
  Total Local Groups:        The total number of local (builtin) groups.

A list of flags representing password policy requirements (when using enumerate=summary):
  PwdComplex:                Password must meet complexity requirements.
  NoAnon:                    No anonymous password changes allowed.
  NoClrChg:                  Clear-text password changes are disallowed.
  LockAdmins:                Lockout applies to administrators.
  StoreClr:                  Store passwords using reversible (cleartext) encryption.
  RefuseChg:                 Refuse password changes under specific conditions.

Additional Notes:
  - This tool requires the Impacket libraries.
  - Ensure you have the appropriate privileges to perform enumeration tasks.
  - Report bugs or contribute to the project at the official repository: https://github.com/studylab1/SAMR-Enum-Lab
"""

import sys
import time
import getpass
from datetime import datetime
from impacket.dcerpc.v5 import transport, samr
import csv, json, csv

# SID_NAME_USE local definitions
SID_NAME_USER = 1
SID_NAME_GROUP = 2
SID_NAME_DOMAIN = 3
SID_NAME_ALIAS = 4
SID_NAME_WKN_GRP = 5

###########################################################
# SAMR FUNCTION -> OPNUM MAPPING
# Official reference from MS-SAMR specification (decimal).
###########################################################
SAMR_FUNCTION_OPNUMS = {
    'SamrConnect': 0,
    'SamrCloseHandle': 1,
    'SamrLookupDomainInSamServer': 5,
    'SamrEnumerateDomainsInSamServer': 6,
    'SamrOpenDomain': 7,
    'SamrEnumerateGroupsInDomain': 11,
    'SamrEnumerateUsersInDomain': 13,
    'SamrEnumerateAliasesInDomain': 15,
    'SamrLookupNamesInDomain': 17,
    'SamrLookupIdsInDomain': 18,
    'SamrOpenGroup': 19,
    'SamrQueryInformationGroup': 20,
    'SamrGetMembersInGroup': 25,
    'SamrOpenAlias': 27,
    'SamrQueryInformationAlias': 28,
    'SamrGetMembersInAlias': 33,
    'SamrOpenUser': 34,
    'SamrQueryInformationUser': 36,
    'SamrGetGroupsForUser': 39,
    'SamrQueryInformationDomain2': 46,
    'SamrQueryInformationUser2': 47,
}

###########################################################
# SAMR FUNCTION -> ACCESS MASK
# Only track calls that actually specify a desiredAccess.
# Others show no Access Mask.
###########################################################
SAMR_FUNCTION_ACCESS = {
    'SamrOpenUser': 0x0002011b,  # USER_LIST_GROUPS
    'SamrConnect': 0x00000031,  # desiredAccess=0x31
    'SamrOpenDomain': 0x00000300,  # DOMAIN_LOOKUP | DOMAIN_LIST_ACCOUNTS
    'SamrOpenGroup': 0x00000010,  # GROUP_LIST_MEMBERS
    'SamrOpenAlias': 0x0000000C,  # ALIAS_LIST_MEMBERS
}


def add_opnum_call(opnums_list, func_name, actual_access=None):
    """
    Append the given SAMR function name, its OpNum, and (if relevant) the Access Mask
    to the tracking list, with the Access Mask inside the parentheses.

    :param opnums_list: List where the SAMR operation details will be appended.
    :param func_name: The name of the SAMR function (e.g., "SamrConnect").
    :param actual_access: (Optional) The actual Access Mask value (int) used, if available.
    :return: None
    """
    opnum = SAMR_FUNCTION_OPNUMS.get(func_name)
    if opnum is not None:
        if actual_access is not None:
            # Show the *actual* Access Mask if provided
            opnums_list.append(f"{func_name} (OpNum {opnum}, Access Mask: 0x{actual_access:08X})")
        else:
            # Fall back to the old dictionary-based Access Mask
            access_val = SAMR_FUNCTION_ACCESS.get(func_name)
            if access_val is not None:
                opnums_list.append(f"{func_name} (OpNum {opnum}, Access Mask: 0x{access_val:08X})")
            else:
                opnums_list.append(f"{func_name} (OpNum {opnum})")
    else:
        # Neither OpNum nor Access is known
        opnums_list.append(func_name)


def format_time(filetime_64):
    """
    Convert a 64-bit Windows FILETIME (100-ns intervals since 1601-01-01)
    into a human-readable string. Returns 'Never' if 0 or 0x7FFFFFFFFFFFFFFF.

    :param filetime_64: 64-bit integer representing Windows FILETIME.
    :return: A formatted date-time string in 'YYYY-MM-DD HH:MM:SS' format, or 'Never'.
    """
    if filetime_64 == 0 or filetime_64 == 0x7FFFFFFFFFFFFFFF:
        return 'Never'
    try:
        # FILETIME is in 100-nanosecond increments, offset from 1601-01-01
        # Convert to seconds from 1970-01-01 by subtracting the Windows->Unix epoch offset
        seconds = filetime_64 / 10000000.0 - 11644473600
        dt = datetime.utcfromtimestamp(seconds)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return 'Invalid timestamp'


def format_date(time_str):
    """
    Convert a time string in 'YYYY-MM-DD HH:MM:SS' format to 'YYYY.MM.DD'.
    If the input is 'Never' or invalid, return it as is.

    :param time_str: A string representing a date and time.
    :return: A date string in 'YYYY.MM.DD' format or the original string if conversion fails.
    """
    if time_str == 'Never' or not time_str:
        return 'Never'
    try:
        return time_str.split(" ")[0].replace('-', '.')
    except Exception:
        return time_str


def to_int_uac(uac_value):
    """
    Safely convert a UserAccountControl (NDRULONG or int) into a Python integer.

    :param uac_value: The UserAccountControl value (could be int, NDR object, or bytes).
    :return: An integer representing the UserAccountControl flags.
    """
    if not uac_value:
        return 0
    # If it's already a plain Python int, return it as-is.
    if isinstance(uac_value, int):
        return uac_value
    # If it's an NDR object with a 'fields' dict, we can extract the 'Data'.
    if hasattr(uac_value, 'fields') and 'Data' in uac_value.fields:
        return uac_value.fields['Data']
    # If it's bytes (unlikely for UAC but let's be safe), convert from little-endian.
    if isinstance(uac_value, bytes):
        return int.from_bytes(uac_value, byteorder='little')
    return 0


def decode_filetime(value):
    """
    Convert an Impacket OLD_LARGE_INTEGER (with HighPart/LowPart) into a 64-bit Windows FILETIME integer.

    :param value: An object with a 'fields' dictionary containing 'HighPart' and 'LowPart'.
    :return: A 64-bit integer representing the FILETIME, or 0 if value is invalid.
    """
    if not value or not hasattr(value, 'fields'):
        return 0

    # Extract the NDR values from HighPart and LowPart
    high_part_ndr = value.fields['HighPart']
    low_part_ndr = value.fields['LowPart']

    high_part_int = extract_ndr_value(high_part_ndr)  # becomes plain int
    low_part_int = extract_ndr_value(low_part_ndr)    # becomes plain int

    # Combine them into a 64-bit integer
    return (high_part_int << 32) | (low_part_int & 0xFFFFFFFF)


def parse_named_args(argv):
    """
    Parse named arguments of the form key=value from the command line.

    :param argv: sys.argv or similar list of command-line tokens
    :return: dict mapping lowercase key -> string value
    Example: python samr-enum.py target=server1 user=admin password=pass123
    """
    args = {}
    for item in argv[1:]:
        if '=' in item:
            key, val = item.split('=', 1)
            args[key.strip().lower()] = val.strip()
    return args


def print_help() -> None:
    """
    Print the help text and exit.

    :return: This function does not return; it exits the program.
    """
    print(HELP_TEXT)
    sys.exit(1)


def yes_no(value):
    """
    Convert a boolean value into 'Yes' or 'No'.
    If the value is not strictly True or False, just return str(value).

    :param value: A boolean value or any value to convert.
    :return: 'Yes' if True, 'No' if False, otherwise str(value).
    """
    if value is True:
        return "Yes"
    elif value is False:
        return "No"
    return str(value)


def log_debug(debug, message):
    """
    Print debugging messages if debug is True.

    :param debug: Boolean indicating whether to print debug info
    :param message: The message to print
    """
    if debug:
        print(message)


def extract_ndr_value(ndr_object):
    """
    Safely extract an integer value from an Impacket NDR object.

    :param ndr_object: The NDR object (could be an int, an object with __int__, or with 'fields').
    :return: A plain Python integer if conversion is successful, else the original object.
    """
    if isinstance(ndr_object, int):
        return ndr_object
    try:
        # Try to convert using the object's __int__ method.
        return int(ndr_object)
    except Exception:
        if hasattr(ndr_object, 'fields') and 'Data' in ndr_object.fields:
            return ndr_object.fields['Data']
    return ndr_object


def safe_str(value):
    """
    Convert a value to a Unicode string safely.
    If the value is an RPC_UNICODE_STRING, extract and decode its Buffer.

    :param value: The value to convert.
    :return: A safe string representation.
    """
    # If already a Python string, return it directly.
    if isinstance(value, str):
        return value
    # If the object has a getData() method, use it.
    if hasattr(value, 'getData') and callable(value.getData):
        try:
            data = value.getData()
            if isinstance(data, str):
                return data
            return str(data)
        except Exception:
            pass
    # If the class name indicates an RPC_UNICODE_STRING, decode the Buffer.
    if hasattr(value, '__class__') and value.__class__.__name__ == 'RPC_UNICODE_STRING':
        try:
            return value.fields['Buffer'].decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return repr(value)
    # Fallback conversion.
    try:
        return str(value)
    except Exception:
        return repr(value)


def decode_group_attributes(attr):
    """
    Decode a group attributes bitmask into a comma-separated string of attribute names.

    :param attr: The integer bitmask.
    :return: A string of attribute names separated by commas.
    """
    flags = []
    if attr & 0x00000001:
        flags.append("Mandatory")
    if attr & 0x00000002:
        flags.append("Enabled by default")
    if attr & 0x00000004:
        flags.append("Enabled")
    if attr & 0x00000008:
        flags.append("Owner")
    if attr & 0x00000010:
        flags.append("Deny only")
    return ", ".join(flags)


def export_data(filename, fmt, data):
    """
    Export enumerated data into a file.
    For display-info type=users objects (i.e. dictionaries that contain a 'last_logon' key),
    export the following columns:
      RID, Last Logon, PwdSet, PwdNE, PwdExp, ForceChg, AccDis, PreAuth, Delg, BadCnt, Username, Full Name
    For display-info type=computers objects, export the following columns in this order:
      RID, Name, Logons, LastLogon, PwdLastSet, BadPwdCnt, PID, Type, Enabled, PwdNReq, PwdNExp, Deleg, Description
    For display-info type=local-groups objects, export the following columns:
      RID, MemCnt, Name, Description
    For account-details objects (from enumerate=account-details) export one attribute per line.
    For other data types, the export behavior remains unchanged.

    :param filename: The name of the file to export to.
    :param fmt: The format ('txt', 'csv', or 'json').
    :param data: The data to export.
    """
    if not filename or not data:
        return

    # If data is a tuple, assume it's for local-groups: (list_of_groups, domain_sid)
    domain_sid = ""
    if isinstance(data, tuple):
        data, domain_sid = data

    supported_formats = ['txt', 'csv', 'json']
    if fmt not in supported_formats:
        print(f"Error: Unsupported format '{fmt}'. Supported: {supported_formats}")
        return

    # Helper to convert a time string to a short date "YYYY.MM.DD"
    def format_date_export(time_str):
        if time_str == 'Never' or not time_str:
            return 'Never'
        try:
            return time_str.split(" ")[0].replace('-', '.')
        except Exception:
            return time_str

    # Helper to export a value for account-details.
    def export_value(key, value):
        # List of keys that represent FILETIME values.
        date_keys = {"last_logon", "password_last_set", "password_can_change", "password_force_change",
                     "account_expires"}
        if key in date_keys:
            return format_date_export(format_time(value))
        return value

    try:
        with open(filename, 'w') as f:
            # ----- Branch for plain computers export (from enumerate=computers) -----
            if isinstance(data[0], dict) and 'computer_name' in data[0]:
                if ('logon_count' not in data[0]) or (
                        str(data[0].get('logon_count')).strip().lower() in ['n/a', 'never', 'none', '']):
                    if fmt == 'txt':
                        max_length = max(len(str(comp.get('computer_name', '')).rstrip('$')) for comp in data)
                        header_line = f"{'Name':<{max_length}} RID"
                        f.write(header_line + "\n")
                        f.write("-" * (max_length + len(" RID") + 2) + "\n")
                        for obj in data:
                            name = str(obj.get('computer_name', '')).rstrip('$')
                            rid = str(obj.get('rid', 'N/A'))
                            f.write(f"{name:<{max_length}} {rid}\n")
                    elif fmt == 'csv':
                        writer = csv.writer(f, delimiter=';')
                        writer.writerow(['Name', 'RID'])
                        for obj in data:
                            writer.writerow([str(obj.get('computer_name', '')).rstrip('$'), obj.get('rid', 'N/A')])
                    elif fmt == 'json':
                        json_data = [{"Name": str(obj.get('computer_name', '')).rstrip('$'),
                                      "RID": obj.get('rid', 'N/A')} for obj in data]
                        json.dump(json_data, f, indent=2)
                else:
                    # Detailed export for computers (from display-info type=computers)
                    header = ["RID", "Name", "Logons", "LastLogon", "PwdLastSet", "BadPwdCnt",
                              "PID", "Type", "Enabled", "PwdNReq", "PwdNExp", "Deleg", "Description"]
                    if fmt == 'txt':
                        col_widths = {
                            "RID": 6,
                            "Name": 18,
                            "Logons": 6,
                            "LastLogon": 11,
                            "PwdLastSet": 11,
                            "BadPwdCnt": 9,
                            "PID": 4,
                            "Type": 14,
                            "Enabled": 8,
                            "PwdNReq": 9,
                            "PwdNExp": 8,
                            "Deleg": 6,
                            "Description": 14
                        }
                        header_line = ""
                        for col in header:
                            header_line += f"{col:<{col_widths[col]}} "
                        f.write(header_line.strip() + "\n")
                        f.write("-" * (sum(col_widths.values()) + len(header)) + "\n")
                        for obj in data:
                            rid = str(obj.get('rid', 'N/A'))
                            name = str(obj.get('computer_name', 'N/A')).rstrip('$')
                            logons = str(obj.get('logon_count', 'N/A'))
                            last_logon = format_date_export(format_time(obj.get('last_logon', 0)))
                            pwd_last_set = format_date_export(format_time(obj.get('password_last_set', 0)))
                            bad_pwd_cnt = str(obj.get('bad_password_count', 'N/A'))
                            pid = str(obj.get('primary_group_id', 'N/A'))
                            trust = obj.get('trust_type', 'N/A')
                            enabled = "Yes" if obj.get('enabled', False) else "No"
                            pwd_nreq = "Yes" if obj.get('password_not_required', False) else "No"
                            pwd_nexp = "Yes" if obj.get('password_never_expires', False) else "No"
                            deleg = obj.get('delegation_status', 'N/A')
                            desc = obj.get('description', 'N/A')
                            row = (f"{rid:<{col_widths['RID']}} "
                                   f"{name:<{col_widths['Name']}} "
                                   f"{logons:<{col_widths['Logons']}} "
                                   f"{last_logon:<{col_widths['LastLogon']}} "
                                   f"{pwd_last_set:<{col_widths['PwdLastSet']}} "
                                   f"{bad_pwd_cnt:<{col_widths['BadPwdCnt']}} "
                                   f"{pid:<{col_widths['PID']}} "
                                   f"{trust:<{col_widths['Type']}} "
                                   f"{enabled:<{col_widths['Enabled']}} "
                                   f"{pwd_nreq:<{col_widths['PwdNReq']}} "
                                   f"{pwd_nexp:<{col_widths['PwdNExp']}} "
                                   f"{deleg:<{col_widths['Deleg']}} "
                                   f"{desc:<{col_widths['Description']}}")
                            f.write(row + "\n")
                    elif fmt == 'csv':
                        writer = csv.writer(f, delimiter=';')
                        writer.writerow(header)
                        for obj in data:
                            rid = str(obj.get('rid', 'N/A'))
                            name = str(obj.get('computer_name', 'N/A')).rstrip('$')
                            logons = obj.get('logon_count', 'N/A')
                            last_logon = format_date_export(format_time(obj.get('last_logon', 0)))
                            pwd_last_set = format_date_export(format_time(obj.get('password_last_set', 0)))
                            bad_pwd_cnt = str(obj.get('bad_password_count', 'N/A'))
                            pid = str(obj.get('primary_group_id', 'N/A'))
                            trust = obj.get('trust_type', 'N/A')
                            enabled = "Yes" if obj.get('enabled', False) else "No"
                            pwd_nreq = "Yes" if obj.get('password_not_required', False) else "No"
                            pwd_nexp = "Yes" if obj.get('password_never_expires', False) else "No"
                            deleg = obj.get('delegation_status', 'N/A')
                            desc = obj.get('description', 'N/A')
                            writer.writerow([rid, name, logons, last_logon, pwd_last_set,
                                             bad_pwd_cnt, pid, trust, enabled, pwd_nreq, pwd_nexp, deleg, desc])
                    elif fmt == 'json':
                        json_data = []
                        for obj in data:
                            rid = str(obj.get('rid', 'N/A'))
                            name = str(obj.get('computer_name', 'N/A')).rstrip('$')
                            logons = obj.get('logon_count', 'N/A')
                            last_logon = format_date_export(format_time(obj.get('last_logon', 0)))
                            pwd_last_set = format_date_export(format_time(obj.get('password_last_set', 0)))
                            bad_pwd_cnt = str(obj.get('bad_password_count', 'N/A'))
                            pid = str(obj.get('primary_group_id', 'N/A'))
                            trust = obj.get('trust_type', 'N/A')
                            enabled = "Yes" if obj.get('enabled', False) else "No"
                            pwd_nreq = "Yes" if obj.get('password_not_required', False) else "No"
                            pwd_nexp = "Yes" if obj.get('password_never_expires', False) else "No"
                            deleg = obj.get('delegation_status', 'N/A')
                            desc = obj.get('description', 'N/A')
                            json_data.append({
                                "RID": rid,
                                "Name": name,
                                "Logons": logons,
                                "LastLogon": last_logon,
                                "PwdLastSet": pwd_last_set,
                                "BadPwdCnt": bad_pwd_cnt,
                                "PID": pid,
                                "Type": trust,
                                "Enabled": enabled,
                                "PwdNReq": pwd_nreq,
                                "PwdNExp": pwd_nexp,
                                "Deleg": deleg,
                                "Description": desc
                            })
                        json.dump(json_data, f, indent=2)
            # ----- Branch for local-groups export -----
            elif isinstance(data[0], dict) and 'group_name' in data[0]:
                # Remove "Domain SID" from the header for TXT and JSON exports
                header = ["RID", "MemCnt", "Name", "Description"]
                if fmt == 'txt':
                    col_widths = {
                        "RID": 6,
                        "MemCnt": 7,
                        "Name": 30,
                        "Description": 40,
                    }
                    header_line = (f"{header[0]:<{col_widths['RID']}} "
                                   f"{header[1]:<{col_widths['MemCnt']}} "
                                   f"{header[2]:<{col_widths['Name']}} "
                                   f"{header[3]:<{col_widths['Description']}}")
                    f.write(header_line + "\n")
                    f.write("-" * (sum(col_widths.values()) + 4) + "\n")
                    for obj in data:
                        rid = str(obj.get('rid', 'N/A'))
                        memcnt = str(obj.get('member_count', 'N/A'))
                        name = safe_str(obj.get('group_name', 'N/A'))
                        desc = safe_str(obj.get('description', ''))
                        row = (f"{rid:<{col_widths['RID']}} "
                               f"{memcnt:<{col_widths['MemCnt']}} "
                               f"{name:<{col_widths['Name']}} "
                               f"{desc:<{col_widths['Description']}}")
                        f.write(row + "\n")
                elif fmt == 'csv':
                    writer = csv.writer(f, delimiter=';')
                    # Export CSV without the Domain SID column
                    writer.writerow(header)
                    for obj in data:
                        rid = str(obj.get('rid', 'N/A'))
                        memcnt = str(obj.get('member_count', 'N/A'))
                        name = safe_str(obj.get('group_name', 'N/A'))
                        desc = safe_str(obj.get('description', ''))
                        writer.writerow([rid, memcnt, name, desc])
                elif fmt == 'json':
                    json_data = []
                    for obj in data:
                        rid = str(obj.get('rid', 'N/A'))
                        memcnt = str(obj.get('member_count', 'N/A'))
                        name = safe_str(obj.get('group_name', 'N/A'))
                        desc = safe_str(obj.get('description', ''))
                        json_data.append({
                            "RID": rid,
                            "MemCnt": memcnt,
                            "Name": name,
                            "Description": desc
                        })
                    json.dump(json_data, f, indent=2)
            # ----- New branch for account-details export -----
            elif isinstance(data[0], dict) and 'home_directory' in data[0] and 'profile_path' in data[0]:
                account_keys = [
                    ("RID", "rid"),
                    ("Username", "username"),
                    ("Full Name", "full_name"),
                    ("Description", "description"),
                    ("Last Logon", "last_logon"),
                    ("Logon Count", "logon_count"),
                    ("Password Last Set", "password_last_set"),
                    ("Password Can Chg", "password_can_change"),
                    ("Password Force Chg", "password_force_change"),
                    ("Password Expired", "password_expired"),
                    ("Password Never Exp-s", "password_never_expires"),
                    ("Password Bad Count", "password_bad_count"),
                    ("Account Expires", "account_expires"),
                    ("Account Disabled", "account_disabled"),
                    ("Pre-Auth. Required", "pre_auth"),
                    ("Delegation Allowed", "delegated"),
                    ("Smartcard Required", "smartcard_required"),
                ]
                additional_keys = [
                    ("Primary Group ID", "primary_gid"),
                    ("Home Directory", "home_directory"),
                    ("Home Drive", "home_drive"),
                    ("Profile Path", "profile_path"),
                    ("Script Path", "script_path"),
                    ("Workstations", "workstations"),
                ]
                if fmt == 'txt':
                    for label, key in account_keys:
                        val = export_value(key, data[0].get(key, 'N/A'))
                        f.write(f"{label}: {val}\n")
                    f.write("\n")
                    for label, key in additional_keys:
                        val = export_value(key, data[0].get(key, 'N/A'))
                        f.write(f"{label}: {val}\n")
                elif fmt == 'csv':
                    writer = csv.writer(f, delimiter=';')
                    for label, key in account_keys + additional_keys:
                        val = export_value(key, data[0].get(key, 'N/A'))
                        writer.writerow([label, val])
                elif fmt == 'json':
                    json.dump(data[0], f, indent=2)
            # ----- Branch for display-info users export -----
            elif isinstance(data[0], dict) and 'last_logon' in data[0]:
                header = ["RID", "Last Logon", "PwdSet", "PwdNE", "PwdExp", "ForceChg",
                          "AccDis", "PreAuth", "Delg", "BadCnt", "Username", "Full Name"]
                if fmt == 'txt':
                    col_widths = {
                        "RID": 8,
                        "Last Logon": 12,
                        "PwdSet": 10,
                        "PwdNE": 10,
                        "PwdExp": 10,
                        "ForceChg": 10,
                        "AccDis": 10,
                        "PreAuth": 10,
                        "Delg": 8,
                        "BadCnt": 10,
                        "Username": 15,
                        "Full Name": 20
                    }
                    header_line = ""
                    for col in header:
                        header_line += f"{col:<{col_widths[col]}} "
                    f.write(header_line.strip() + "\n")
                    f.write("-" * (sum(col_widths.values()) + len(header)) + "\n")
                    for obj in data:
                        rid = str(obj.get('rid', 'N/A'))
                        last_logon = format_date_export(format_time(obj.get('last_logon', 0)))
                        pwd_set = format_date_export(format_time(obj.get('password_last_set', 0)))
                        pwd_ne = "Yes" if obj.get('password_never_expires', False) else "No"
                        pwd_exp = "Yes" if obj.get('password_expired', False) else "No"
                        force_chg = format_date_export(format_time(obj.get('password_force_change', 0)))
                        acc_dis = "Yes" if obj.get('account_disabled', False) else "No"
                        pre_auth = "Yes" if obj.get('pre_auth', False) else "No"
                        delegated = "Yes" if obj.get('delegated', False) else "No"
                        bad_cnt = str(obj.get('password_bad_count', 'N/A'))
                        username_val = obj.get('username', 'N/A')
                        full_name = obj.get('full_name', 'N/A')
                        row = (f"{rid:<{col_widths['RID']}} "
                               f"{last_logon:<{col_widths['Last Logon']}} "
                               f"{pwd_set:<{col_widths['PwdSet']}} "
                               f"{pwd_ne:<{col_widths['PwdNE']}} "
                               f"{pwd_exp:<{col_widths['PwdExp']}} "
                               f"{force_chg:<{col_widths['ForceChg']}} "
                               f"{acc_dis:<{col_widths['AccDis']}} "
                               f"{pre_auth:<{col_widths['PreAuth']}} "
                               f"{delegated:<{col_widths['Delg']}} "
                               f"{bad_cnt:<{col_widths['BadCnt']}} "
                               f"{username_val:<{col_widths['Username']}} "
                               f"{full_name:<{col_widths['Full Name']}}")
                        f.write(row + "\n")
                # [CSV and JSON branches for users remain unchanged...]
                elif fmt == 'csv':
                    writer = csv.writer(f, delimiter=';')
                    writer.writerow(header)
                    for obj in data:
                        rid = str(obj.get('rid', 'N/A'))
                        last_logon = format_date_export(format_time(obj.get('last_logon', 0)))
                        pwd_set = format_date_export(format_time(obj.get('password_last_set', 0)))
                        pwd_ne = "Yes" if obj.get('password_never_expires', False) else "No"
                        pwd_exp = "Yes" if obj.get('password_expired', False) else "No"
                        force_chg = format_date_export(format_time(obj.get('password_force_change', 0)))
                        acc_dis = "Yes" if obj.get('account_disabled', False) else "No"
                        pre_auth = "Yes" if obj.get('pre_auth', False) else "No"
                        delegated = "Yes" if obj.get('delegated', False) else "No"
                        bad_cnt = str(obj.get('password_bad_count', 'N/A'))
                        username_val = obj.get('username', 'N/A')
                        full_name = obj.get('full_name', 'N/A')
                        writer.writerow([rid, last_logon, pwd_set, pwd_ne, pwd_exp, force_chg,
                                         acc_dis, pre_auth, delegated, bad_cnt, username_val, full_name])
                elif fmt == 'json':
                    json_data = []
                    for obj in data:
                        rid = str(obj.get('rid', 'N/A'))
                        last_logon = format_date_export(format_time(obj.get('last_logon', 0)))
                        pwd_set = format_date_export(format_time(obj.get('password_last_set', 0)))
                        pwd_ne = "Yes" if obj.get('password_never_expires', False) else "No"
                        pwd_exp = "Yes" if obj.get('password_expired', False) else "No"
                        force_chg = format_date_export(format_time(obj.get('password_force_change', 0)))
                        acc_dis = "Yes" if obj.get('account_disabled', False) else "No"
                        pre_auth = "Yes" if obj.get('pre_auth', False) else "No"
                        delegated = "Yes" if obj.get('delegated', False) else "No"
                        bad_cnt = str(obj.get('password_bad_count', 'N/A'))
                        username_val = obj.get('username', 'N/A')
                        full_name = obj.get('full_name', 'N/A')
                        json_data.append({
                            "RID": rid,
                            "Last Logon": last_logon,
                            "PwdSet": pwd_set,
                            "PwdNE": pwd_ne,
                            "PwdExp": pwd_exp,
                            "ForceChg": force_chg,
                            "AccDis": acc_dis,
                            "PreAuth": pre_auth,
                            "Delg": delegated,
                            "BadCnt": bad_cnt,
                            "Username": username_val,
                            "Full Name": full_name
                        })
                    json.dump(json_data, f, indent=2)

            # Branch for summary export
            elif isinstance(data[0], dict) and 'domain_info' in data[0]:
                # In summary, the exported data is a single dictionary.
                summary = data[0]
                domain_info = summary.get('domain_info', {})
                password_policy = summary.get('password_policy', {})
                lockout_policy = summary.get('lockout_policy', {})

                if fmt == 'txt':
                    # Produce a multi-line output similar to on-screen output.
                    f.write("Domain Information:\n")
                    f.write(f"  Domain SID:               {domain_info.get('domain_sid', 'N/A')}\n")
                    f.write(f"  Domain Name:              {domain_info.get('domain_name', 'N/A')}\n")
                    f.write(f"  UAS Compatible:           {yes_no(domain_info.get('uas_compatible', False))}\n")
                    f.write(f"  Lockout Threshold:        {domain_info.get('lockout_threshold', 'N/A')}\n")
                    f.write(f"  Lockout Duration (days):  {domain_info.get('lockout_duration_days', 'N/A')}\n")
                    f.write(f"  Lockout Observation (days): {domain_info.get('lockout_window_days', 'N/A')}\n")
                    f.write(f"  Force Logoff (days):      {domain_info.get('force_logoff_days', 'N/A')}\n")
                    f.write("\n")
                    f.write("Password Policy:\n")
                    f.write(f"  Minimum Password Length:  {password_policy.get('min_length', 'N/A')}\n")
                    f.write(f"  Minimum Password Age (days): {password_policy.get('min_age_days', 'N/A')}\n")
                    f.write(f"  Maximum Password Age (days): {password_policy.get('max_age_days', 'N/A')}\n")
                    f.write(f"  Password History Length:  {password_policy.get('history_length', 'N/A')}\n")
                    f.write(f"  Password Properties:      {', '.join(password_policy.get('properties', []))}\n")
                    f.write("\n")
                    f.write("Lockout Policy:\n")
                    f.write(f"  Lockout Threshold:        {lockout_policy.get('lockout_threshold', 'N/A')}\n")
                    f.write(f"  Lockout Duration (days):  {lockout_policy.get('lockout_duration', 'N/A')}\n")
                    f.write(f"  Lockout Observation (days): {lockout_policy.get('lockout_window', 'N/A')}\n")
                    f.write("\n")
                    f.write(f"Total Users:               {summary.get('total_users', 'N/A')}\n")
                    f.write(f"Total Domain Groups:       {summary.get('total_domain_groups', 'N/A')}\n")
                    f.write(f"Total Local Groups:        {summary.get('total_local_groups', 'N/A')}\n")
                    f.write(f"Total Computers:           {summary.get('total_computers', 'N/A')}\n")

                elif fmt == 'csv':
                    # For CSV, output key,value pairs in two columns
                    writer = csv.writer(f, delimiter=';')
                    writer.writerow(["Field", "Value"])
                    writer.writerow(["Domain SID", domain_info.get('domain_sid', 'N/A')])
                    writer.writerow(["Domain Name", domain_info.get('domain_name', 'N/A')])
                    writer.writerow(["UAS Compatible", yes_no(domain_info.get('uas_compatible', False))])
                    writer.writerow(["Lockout Threshold", domain_info.get('lockout_threshold', 'N/A')])
                    writer.writerow(["Lockout Duration (days)", domain_info.get('lockout_duration_days', 'N/A')])
                    writer.writerow(["Lockout Observation (days)", domain_info.get('lockout_window_days', 'N/A')])
                    writer.writerow(["Force Logoff (days)", domain_info.get('force_logoff_days', 'N/A')])
                    writer.writerow(["Minimum Password Length", password_policy.get('min_length', 'N/A')])
                    writer.writerow(["Minimum Password Age (days)", password_policy.get('min_age_days', 'N/A')])
                    writer.writerow(["Maximum Password Age (days)", password_policy.get('max_age_days', 'N/A')])
                    writer.writerow(["Password History Length", password_policy.get('history_length', 'N/A')])
                    writer.writerow(["Password Properties", ", ".join(password_policy.get('properties', []))])
                    writer.writerow(["Total Users", summary.get('total_users', 'N/A')])
                    writer.writerow(["Total Domain Groups", summary.get('total_domain_groups', 'N/A')])
                    writer.writerow(["Total Local Groups", summary.get('total_local_groups', 'N/A')])
                    writer.writerow(["Total Computers", summary.get('total_computers', 'N/A')])

                elif fmt == 'json':
                    # In JSON, include all fields (ensure password properties are added)
                    json_data = {
                        "Domain SID": domain_info.get('domain_sid', 'N/A'),
                        "Domain Name": domain_info.get('domain_name', 'N/A'),
                        "UAS Compatible": yes_no(domain_info.get('uas_compatible', False)),
                        "Lockout Threshold": domain_info.get('lockout_threshold', 'N/A'),
                        "Lockout Duration (days)": domain_info.get('lockout_duration_days', 'N/A'),
                        "Lockout Observation (days)": domain_info.get('lockout_window_days', 'N/A'),
                        "Force Logoff (days)": domain_info.get('force_logoff_days', 'N/A'),
                        "Minimum Password Length": password_policy.get('min_length', 'N/A'),
                        "Minimum Password Age (days)": password_policy.get('min_age_days', 'N/A'),
                        "Maximum Password Age (days)": password_policy.get('max_age_days', 'N/A'),
                        "Password History Length": password_policy.get('history_length', 'N/A'),
                        "Password Properties": password_policy.get('properties', []),
                        "Total Users": summary.get('total_users', 'N/A'),
                        "Total Domain Groups": summary.get('total_domain_groups', 'N/A'),
                        "Total Local Groups": summary.get('total_local_groups', 'N/A'),
                        "Total Computers": summary.get('total_computers', 'N/A')
                    }
                    json.dump(json_data, f, indent=2)

            elif isinstance(data[0], tuple) and len(data[0]) >= 2:
                # Assume the tuple is (Name, RID)
                if fmt == 'txt':
                    max_length = max(len(str(item[0])) for item in data)
                    header_line = f"{'Name':<{max_length}} RID"
                    f.write(header_line + "\n")
                    f.write("-" * (max_length + len(" RID") + 2) + "\n")
                    for item in data:
                        f.write(f"{item[0]:<{max_length}} {item[1]}\n")
                elif fmt == 'csv':
                    writer = csv.writer(f, delimiter=';')
                    writer.writerow(['Name', 'RID'])
                    for item in data:
                        writer.writerow([item[0], item[1]])
                elif fmt == 'json':
                    json_data = [{"Name": item[0], "RID": item[1]} for item in data]
                    json.dump(json_data, f, indent=2)

            # ----- Branch for local-group-details export -----
            elif isinstance(data[0], dict) and 'alias_name' in data[0]:
                # If the group details include members, export header info then members table
                if 'members' in data[0]:
                    # Export the group header info
                    f.write(f"Local Group Name:\t{data[0].get('alias_name', 'N/A')}\n")
                    f.write(f"RID:\t{data[0].get('rid', 'N/A')}\n")
                    f.write(f"Member Count:\t{data[0].get('member_count', 'N/A')}\n")
                    # If available, also print the primary domain SID
                    if data[0].get('primary_domain_sid'):
                        f.write(f"Domain SID:\t{data[0].get('primary_domain_sid', 'N/A')}\n")
                    # Add an empty line before the member list
                    f.write("\n")
                    # Now export the members table header
                    header_line = f"{'RID':<10}\t{'Username':<20}"
                    f.write(header_line + "\n")
                    f.write("-" * (10 + 20 + 4) + "\n")
                    # Then export each member row
                    for member in data[0].get('members', []):
                        # Assume member is a tuple of (rid, username)
                        rid_member = str(member[0])
                        username_member = str(member[1])
                        f.write(f"{rid_member:<10}\t{username_member:<20}\n")
                else:
                    # Fallback export if no members key exists: export group header only
                    header = ["RID", "Name", "Member Count"]
                    if fmt == 'txt':
                        col_widths = {"RID": 6, "Name": 30, "Member Count": 12}
                        header_line = f"{header[0]:<{col_widths['RID']}} {header[1]:<{col_widths['Name']}} {header[2]:<{col_widths['Member Count']}}"
                        f.write(header_line + "\n")
                        f.write("-" * (sum(col_widths.values()) + 2) + "\n")
                        for obj in data:
                            rid = str(obj.get('rid', 'N/A'))
                            name = safe_str(obj.get('alias_name', 'N/A'))
                            memcnt = str(obj.get('member_count', 'N/A'))
                            row = f"{rid:<{col_widths['RID']}} {name:<{col_widths['Name']}} {memcnt:<{col_widths['Member Count']}}"
                            f.write(row + "\n")
                    elif fmt == 'csv':
                        writer = csv.writer(f, delimiter=';')
                        writer.writerow(header)
                        for obj in data:
                            rid = str(obj.get('rid', 'N/A'))
                            name = safe_str(obj.get('alias_name', 'N/A'))
                            memcnt = str(obj.get('member_count', 'N/A'))
                            writer.writerow([rid, name, memcnt])
                    elif fmt == 'json':
                        # Build a new dictionary with formatted values for account details.
                        account_keys = [
                            ("RID", "rid"),
                            ("Username", "username"),
                            ("Full Name", "full_name"),
                            ("Description", "description"),
                            ("Last Logon", "last_logon"),
                            ("Logon Count", "logon_count"),
                            ("Password Last Set", "password_last_set"),
                            ("Password Can Chg", "password_can_change"),
                            ("Password Force Chg", "password_force_change"),
                            ("Password Expired", "password_expired"),
                            ("Password Never Exp-s", "password_never_expires"),
                            ("Password Bad Count", "password_bad_count"),
                            ("Account Expires", "account_expires"),
                            ("Account Disabled", "account_disabled"),
                            ("Pre-Auth. Required", "pre_auth"),
                            ("Delegation Allowed", "delegated"),
                            ("Smartcard Required", "smartcard_required"),
                        ]
                        additional_keys = [
                            ("Primary Group ID", "primary_gid"),
                            ("Home Directory", "home_directory"),
                            ("Home Drive", "home_drive"),
                            ("Profile Path", "profile_path"),
                            ("Script Path", "script_path"),
                            ("Workstations", "workstations"),
                        ]
                        export_dict = {}
                        # For the date fields in account_keys, export_value applies formatting.
                        for label, key in account_keys:
                            export_dict[label] = export_value(key, data[0].get(key, 'N/A'))
                        for label, key in additional_keys:
                            export_dict[label] = export_value(key, data[0].get(key, 'N/A'))
                        json.dump(export_dict, f, indent=2)

            else:
                # Fallback for other data types remains unchanged.
                f.write("Unknown data format for export.\n")
        print(f"Data exported to {filename} ({fmt.upper()})")
    except Exception as e:
        print(f"Export failed: {str(e)}")


def enumerate_local_groups_plain(dce, serverHandle, debug, opnums_called):
    """
    Enumerate local (Builtin) groups using the plain method.
    This is used when the user specifies "enumerate=local-groups" so that
    no additional OpNum 28 (SamrQueryInformationAlias) is sent.

    :param dce: The DCE/RPC connection object.
    :param serverHandle: The SAMR server handle.
    :param debug: Boolean flag indicating whether debug messages should be printed.
    :param opnums_called: A list used to record the SAMR operation numbers (OpNums) invoked.
    :return: A tuple containing:
             - A list of dictionaries, each with details about a local group (group name, RID, and member count).
             - The domain SID string.
    """
    # Get the Builtin domain handle (which is used for local groups)
    builtinHandle, builtinName, domainSidString = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
    try:
        aliasResp = samr.hSamrEnumerateAliasesInDomain(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrEnumerateAliasesInSamServer")
        aliases = aliasResp['Buffer']['Buffer'] or []
    except Exception as e:
        aliases = []
    results = []
    for alias in aliases:
        alias_name = safe_str(alias['Name'])
        try:
            details = get_local_group_details_plain(dce, builtinHandle, alias_name, debug, opnums_called)
            results.append(details)
        except Exception as e:
            results.append({'group_name': alias_name, 'error': str(e)})
    samr.hSamrCloseHandle(dce, builtinHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")
    return results, domainSidString


def get_local_group_details_plain(dce, builtinHandle, alias_name, debug, opnums_called):
    """
    Retrieve local group (alias) details without extra SID resolution.
    This mimics the working version (version 1) for local groups.

    :param dce: The DCE/RPC connection object.
    :param builtinHandle: The handle to the Builtin domain.
    :param alias_name: The name of the local group (alias) to retrieve details for.
    :param debug: Boolean flag indicating whether debug messages should be printed.
    :param opnums_called: A list used to record the SAMR operation numbers (OpNums) invoked.
    :return: A dictionary containing the local group details:
             - 'group_name': The alias (local group) name.
             - 'rid': The Relative Identifier (RID) of the alias.
             - 'member_count': The number of members in the alias.
    """
    lookupResp = samr.hSamrLookupNamesInDomain(dce, builtinHandle, [alias_name])
    add_opnum_call(opnums_called, "SamrLookupNamesInSamServer")
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) != SID_NAME_ALIAS:
        raise Exception(f"Alias '{alias_name}' not found or not a valid alias.")
    alias_rid = extract_ndr_value(rids[0])

    aliasHandle = samr.hSamrOpenAlias(dce, builtinHandle, samr.ALIAS_LIST_MEMBERS, alias_rid)['AliasHandle']
    add_opnum_call(opnums_called, "SamrOpenAlias")

    membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInAlias")
    member_count = len(membersResp['Members']['Sids'])

    samr.hSamrCloseHandle(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    return {'group_name': alias_name, 'rid': alias_rid, 'member_count': member_count}


def samr_connect(target, username, password, domain, debug, auth_mode):
    """
    Connect to \\pipe\\samr on the remote target and return (dce, serverHandle).
    If auth_mode=='kerberos', sets Kerberos = True in the transport.

    desiredAccess=0x00000031 for SamrConnect

    :param target: Hostname or IP of the remote target
    :param username: The username for authentication
    :param password: The password for authentication (could be empty, then user is prompted)
    :param domain: The domain of the user (can be blank if not needed)
    :param debug: Boolean indicating debug output
    :param auth_mode: "kerberos" or "ntlm" (default)
    :return: (dce, serverHandle)
    """
    binding_str = rf"ncacn_np:{target}[\pipe\samr]"
    log_debug(debug, f"[debug] Using binding string: {binding_str}")
    rpc_transport = transport.DCERPCTransportFactory(binding_str)

    # If auth=kerberos, set Kerberos usage on the transport
    if auth_mode.lower() == 'kerberos':
        log_debug(debug, "[debug] Setting Kerberos auth on the transport.")
        rpc_transport.set_kerberos(True)
    else:
        log_debug(debug, "[debug] Using NTLM (default).")

    rpc_transport.set_credentials(username, password, domain=domain)

    dce = rpc_transport.get_dce_rpc()
    log_debug(debug, f"[debug] Connecting to {target} via SMB (auth={auth_mode})...")
    dce.connect()

    log_debug(debug, "[debug] Binding to SAMR interface (MSRPC_UUID_SAMR)...")
    dce.bind(samr.MSRPC_UUID_SAMR)

    log_debug(debug, "[debug] Calling SamrConnect...")
    connectResp = samr.hSamrConnect(dce, serverName=target, desiredAccess=0x00000031)

    if debug:
        print("[debug] SamrConnect response dump:")
        print(connectResp.dump())

    if connectResp['ErrorCode'] != 0:
        raise Exception(f"SamrConnect failed (NTSTATUS=0x{connectResp['ErrorCode']:X})")

    serverHandle = connectResp['ServerHandle']
    log_debug(debug, "[debug] SamrConnect succeeded.")
    return dce, serverHandle


def get_domain_handle(dce, serverHandle, debug, opnums_called):
    """
    Enumerate the first domain from SamrEnumerateDomainsInSamServer,
    look up the domain SID, and open the domain handle.
    SamrOpenDomain uses desiredAccess=0x00000300
    (DOMAIN_LOOKUP | DOMAIN_LIST_ACCOUNTS).

    :param dce: The DCE/RPC connection object.
    :param serverHandle: The handle to the SAMR server.
    :param debug: Boolean indicating debug output.
    :param opnums_called: List tracking SAMR operations performed.
    :return: (domainHandle, domainName, sidString)
    """
    log_debug(debug, "[debug] SamrEnumerateDomainsInSamServer -> enumerating domains...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
    add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
    if debug:
        print("[debug] SamrEnumerateDomainsInSamServer response dump:")
        print(enumDomainsResp.dump())

    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on target.")

    domainName = safe_str(domains[0]['Name'])
    log_debug(debug, f"[debug] Found domain: {domainName}")

    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
    add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
    if debug:
        print("[debug] SamrLookupDomainInSamServer response dump:")
        print(lookupResp.dump())

    domainSidObj = lookupResp['DomainId']
    sidString = domainSidObj.formatCanonical()
    log_debug(debug, f"[debug] Domain SID: {sidString}")

    log_debug(debug, "[debug] SamrOpenDomain -> opening domain handle...")
    desired_access = samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_READ_PASSWORD_PARAMETERS
    openDomResp = samr.hSamrOpenDomain(
        dce,
        serverHandle,
        samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_READ_PASSWORD_PARAMETERS,
        domainSidObj
    )
    add_opnum_call(opnums_called, "SamrOpenDomain", desired_access)
    if debug:
        print("[debug] SamrOpenDomain response dump:")
        print(openDomResp.dump())

    if openDomResp['ErrorCode'] != 0:
        raise Exception(f"SamrOpenDomain failed (NTSTATUS=0x{openDomResp['ErrorCode']:X})")

    domainHandle = openDomResp['DomainHandle']
    log_debug(debug, "[debug] Domain opened successfully.")
    return domainHandle, domainName, sidString


def get_builtin_domain_handle(dce, serverHandle, debug, opnums_called):
    """
    Enumerate the domain list, find the one named "Builtin", then open it.
    (DOMAIN_LOOKUP | DOMAIN_LIST_ACCOUNTS).

    :param dce: The DCE/RPC connection object.
    :param serverHandle: The handle to the SAMR server.
    :param debug: Boolean indicating debug output.
    :param opnums_called: List tracking SAMR operations performed.
    :return: (domainHandle, domainName, sidString)
    :raises Exception: If the Builtin domain is not found or opening fails.
    """
    log_debug(debug, "[debug] SamrEnumerateDomainsInSamServer -> looking for Builtin domain...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
    add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
    if debug:
        print("[debug] SamrEnumerateDomainsInSamServer response dump:")
        print(enumDomainsResp.dump())

    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on target.")

    builtin_domain = None
    for dom in domains:
        d_name = safe_str(dom['Name'])
        if d_name.lower() == 'builtin':
            builtin_domain = d_name
            break

    if not builtin_domain:
        raise Exception("Builtin domain not found on target.")

    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, builtin_domain)
    add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
    if debug:
        print("[debug] SamrLookupDomainInSamServer (Builtin) response dump:")
        print(lookupResp.dump())

    domainSidObj = lookupResp['DomainId']
    sidString = domainSidObj.formatCanonical()
    log_debug(debug, f"[debug] Builtin Domain SID: {sidString}")

    log_debug(debug, "[debug] SamrOpenDomain -> opening Builtin domain handle...")
    desired_access = 0x00000300
    openDomResp = samr.hSamrOpenDomain(dce, serverHandle, desired_access, domainSidObj)
    add_opnum_call(opnums_called, "SamrOpenDomain", desired_access)
    if debug:
        print("[debug] SamrOpenDomain (Builtin) response dump:")
        print(openDomResp.dump())

    if openDomResp['ErrorCode'] != 0:
        raise Exception(f"SamrOpenDomain failed for Builtin domain (NTSTATUS=0x{openDomResp['ErrorCode']:X})")

    domainHandle = openDomResp['DomainHandle']
    log_debug(debug, "[debug] Builtin Domain opened successfully.")
    return domainHandle, builtin_domain, sidString


def enumerate_users(dce, domainHandle, debug):
    """
    Enumerate all domain users by repeatedly calling SamrEnumerateUsersInDomain
    until the server no longer returns STATUS_MORE_ENTRIES.

    :param dce: The DCE/RPC connection.
    :param domainHandle: The opened domain handle.
    :param debug: Boolean for debug prints.
    :return: A list of (username, rid) tuples.
    """
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating users...")
    users = []
    resumeHandle = 0
    max_retries = 3
    retry_count = 0

    while True:
        try:
            enumUsersResp = samr.hSamrEnumerateUsersInDomain(
                dce,
                domainHandle,
                enumerationContext=resumeHandle,
                userAccountControl=samr.USER_NORMAL_ACCOUNT
            )
            retry_count = 0

        except samr.DCERPCSessionError as e:
            if e.get_error_code() == 0x00000105:  # STATUS_MORE_ENTRIES
                enumUsersResp = e.get_packet()
                retry_count = 0
            elif e.get_error_code() == 0xC000009A:  # STATUS_INSUFFICIENT_RESOURCES
                log_debug(debug, "[debug] Server busy, retrying after delay...")
                time.sleep(2)
                retry_count += 1
                if retry_count > max_retries:
                    raise Exception("Server resource limit reached after retries")
                continue
            else:
                raise

        chunk = enumUsersResp['Buffer']['Buffer'] or []
        for userEntry in chunk:
            username = safe_str(userEntry['Name'])
            rid = userEntry['RelativeId']
            users.append((username, rid))

        resumeHandle = enumUsersResp['EnumerationContext']
        if enumUsersResp['ErrorCode'] != 0x00000105:
            break
        time.sleep(0.1)

    return users


def enumerate_computers(dce, domainHandle, debug):
    """
    Enumerate all domain computers (workstations AND domain controllers) by
    using both USER_WORKSTATION_TRUST_ACCOUNT and USER_SERVER_TRUST_ACCOUNT flags.
    Returns a list of dictionaries with all fields returned by the server.

    :param dce: The DCE/RPC connection.
    :param domainHandle: The opened domain handle.
    :param debug: Boolean to enable debug output.
    :return: List of dictionaries with computer details.
    """
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating computers...")
    computers = []
    resumeHandle = 0
    max_retries = 3
    retry_count = 0

    # Combined flags for both workstation and server trust accounts
    ACCOUNT_FILTER = samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_SERVER_TRUST_ACCOUNT

    while True:
        try:
            enumUsersResp = samr.hSamrEnumerateUsersInDomain(
                dce,
                domainHandle,
                enumerationContext=resumeHandle,
                userAccountControl=ACCOUNT_FILTER
            )
            retry_count = 0
        except samr.DCERPCSessionError as e:
            if e.get_error_code() == 0x00000105:  # STATUS_MORE_ENTRIES
                enumUsersResp = e.get_packet()
                retry_count = 0
            elif e.get_error_code() == 0xC000009A:  # STATUS_INSUFFICIENT_RESOURCES
                log_debug(debug, "[debug] Server busy, retrying after delay...")
                time.sleep(2)
                retry_count += 1
                if retry_count > max_retries:
                    raise Exception("Server resource limit reached after retries")
                continue
            else:
                raise

        chunk = enumUsersResp['Buffer']['Buffer'] or []
        for accountEntry in chunk:
            computername = safe_str(accountEntry['Name'])
            rid = accountEntry['RelativeId']
            # Build a dictionary with basic details...
            computer_dict = {'computer_name': computername, 'rid': rid}
            # If additional fields exist, add them (skipping Name and RelativeId)
            if hasattr(accountEntry, 'fields'):
                for field, value in accountEntry.fields.items():
                    if field not in ['Name', 'RelativeId']:
                        computer_dict[field] = safe_str(value)
            computers.append(computer_dict)

        resumeHandle = enumUsersResp['EnumerationContext']
        if enumUsersResp['ErrorCode'] != 0x00000105:
            break
        time.sleep(0.1)

    return computers


def enumerate_domain_groups(dce, domainHandle, debug):
    """
    Enumerate domain groups.

    :param dce: The DCE/RPC connection
    :param domainHandle: Handle to the opened domain
    :param debug: Boolean indicating debug output
    :return: (list_of_groups_plus_aliases, did_aliases_bool)
    """
    log_debug(debug, "[debug] SamrEnumerateGroupsInDomain -> enumerating groups...")
    enumGroupsResp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle)
    if debug:
        print("[debug] SamrEnumerateGroupsInDomain response dump:")
        print(enumGroupsResp.dump())

    groups = enumGroupsResp['Buffer']['Buffer'] or []
    group_tuples = [(safe_str(g['Name']), g['RelativeId']) for g in groups]
    return group_tuples, False


def list_domain_group_members(dce, serverHandle, domainHandle, groupName, debug, opnums_called):
    """
    Enumerate members of domain groups with name resolution

    :param dce: The DCE/RPC connection object.
    :param serverHandle: The handle to the SAMR server.
    :param domainHandle: The handle to the domain.
    :param groupName: The name of the domain group whose members are to be enumerated.
    :param debug: Boolean flag for enabling debug output.
    :param opnums_called: List that tracks SAMR operations performed.
    :return: A tuple (results, additional_ops) where results is a list of (member_name, member_rid) pairs.
    """
    log_debug(debug, f"[debug] Domain group lookup: {groupName}")
    additional_ops = ["SamrLookupNamesInDomain"]

    # Lookup group in primary domain
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [groupName])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")

    if debug:
        print("[debug] SamrLookupNamesInDomain response:")
        print(lookupResp.dump())

    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']

    if not rids or extract_ndr_value(uses[0]) not in (SID_NAME_GROUP, SID_NAME_WKN_GRP):
        raise Exception("Not a valid domain group")

    groupRid = extract_ndr_value(rids[0])

    # Open domain group
    add_opnum_call(opnums_called, "SamrOpenGroup")
    groupHandle = samr.hSamrOpenGroup(
        dce, domainHandle, samr.GROUP_LIST_MEMBERS, groupRid
    )['GroupHandle']

    # Get members
    add_opnum_call(opnums_called, "SamrGetMembersInGroup")
    membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)

    # Proper RID extraction matching working user enumeration
    rids_list = []
    for ridEntry in membersResp['Members']['Members']:
        if isinstance(ridEntry, int):
            rids_list.append(ridEntry)
        elif hasattr(ridEntry, 'fields'):
            ridVal = extract_ndr_value(ridEntry)
            rids_list.append(ridVal)
        else:
            ridVal = extract_ndr_value(ridEntry['RelativeId'])
            rids_list.append(ridVal)

    # Resolve RIDs to names
    add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
    lookupResp2 = samr.hSamrLookupIdsInDomain(dce, domainHandle, rids_list)
    names = [safe_str(name['Data']) for name in lookupResp2['Names']['Element']]
    results = list(zip(names, rids_list))

    samr.hSamrCloseHandle(dce, groupHandle)
    additional_ops.append("SamrCloseHandle")

    return results, additional_ops


def list_user_local_memberships(dce, serverHandle, username, domain_sid, debug, opnums_called):
    """
    Check Builtin domain aliases for user SID membership

    :param dce: The DCE/RPC connection object.
    :param serverHandle: The handle to the SAMR server.
    :param username: The username for which to check local group memberships.
    :param domain_sid: The domain SID as a string.
    :param debug: Boolean indicating whether debug output is enabled.
    :param opnums_called: List to track SAMR operations invoked.
    :return: A list of (alias_name, alias_rid) tuples representing local groups the user belongs to.
    """
    # Get user RID from primary domain
    domainHandle, _, _ = get_domain_handle(dce, serverHandle, debug, opnums_called)
    try:
        log_debug(debug, f"[debug] Looking up user '{username}' in primary domain...")
        lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
        add_opnum_call(opnums_called, "SamrLookupNamesInDomain")

        rids = lookupResp['RelativeIds']['Element']
        uses = lookupResp['Use']['Element']
        if not rids or extract_ndr_value(uses[0]) != SID_NAME_USER:
            raise Exception(f"User '{username}' not found in primary domain")

        user_rid = extract_ndr_value(rids[0])
        user_sid = f"{domain_sid}-{user_rid}"

    finally:
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    # Check Builtin domain aliases
    builtinHandle, _, _ = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
    local_memberships = []
    try:
        enumAliasesResp = samr.hSamrEnumerateAliasesInDomain(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")

        for alias in enumAliasesResp['Buffer']['Buffer']:

            # For each alias, call SamrOpenAlias
            add_opnum_call(opnums_called, "SamrOpenAlias")
            aliasHandle = samr.hSamrOpenAlias(
                dce, builtinHandle, samr.ALIAS_LIST_MEMBERS, alias['RelativeId']
            )['AliasHandle']
            try:
                # Then SamrGetMembersInAlias
                add_opnum_call(opnums_called, "SamrGetMembersInAlias")
                membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)

                # Check if the user SID is among those members
                if any(sid['SidPointer'].formatCanonical() == user_sid
                       for sid in membersResp['Members']['Sids']):
                    local_memberships.append(
                        (safe_str(alias['Name']), alias['RelativeId'])
                    )
            finally:
                # Always log SamrCloseHandle for each alias handle
                add_opnum_call(opnums_called, "SamrCloseHandle")
                samr.hSamrCloseHandle(dce, aliasHandle)

    finally:
        # Close the Builtin domain handle as well
        samr.hSamrCloseHandle(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    return local_memberships


def list_user_domain_memberships(dce, domainHandle, username, domain_sid, debug, opnums_called):
    """
    Enumerate domain groups a user belongs to using SamrGetGroupsForUser

    :param dce: The DCE/RPC connection object.
    :param domainHandle: The handle to the domain.
    :param username: The username for which to enumerate domain group memberships.
    :param domain_sid: The domain SID string.
    :param debug: Boolean flag for enabling debug messages.
    :param opnums_called: List tracking SAMR operations performed.
    :return: A list of tuples (group_name, group_rid, attributes) for each domain group membership.
    """
    log_debug(debug, f"[debug] Looking up user '{username}' in domain...")
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")

    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) != SID_NAME_USER:
        raise Exception(f"User '{username}' not found")

    user_rid = extract_ndr_value(rids[0])
    log_debug(debug, f"[debug] User RID: {user_rid}")

    userHandle = samr.hSamrOpenUser(dce, domainHandle, samr.USER_LIST_GROUPS, user_rid)['UserHandle']
    add_opnum_call(opnums_called, "SamrOpenUser")

    groupsResp = samr.hSamrGetGroupsForUser(dce, userHandle)
    add_opnum_call(opnums_called, "SamrGetGroupsForUser")

    samr.hSamrCloseHandle(dce, userHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    if not groupsResp['Groups']['Groups']:
        return []
    group_rids = [g['RelativeId'] for g in groupsResp['Groups']['Groups']]
    lookupGroupsResp = samr.hSamrLookupIdsInDomain(dce, domainHandle, group_rids)
    add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
    groups_list = groupsResp['Groups']['Groups']
    return [
        (safe_str(lookup_name['Data']), g['RelativeId'], g['Attributes'])
        for g, lookup_name in zip(groups_list, lookupGroupsResp['Names']['Element'])
    ]


def get_user_details(dce, domainHandle, user_input, debug, opnums_called):
    """
    Retrieve detailed user information from SAMR using direct dictionary indexing.

    :param dce: The DCE/RPC connection object.
    :param domainHandle: The handle to the domain where the user resides.
    :param user_input: A string representing the username or RID of the user.
    :param debug: Boolean flag to enable debug output.
    :param opnums_called: List that records SAMR operations performed during lookup.
    :return: A dictionary containing detailed user information.
    """
    # First, perform the lookup for the user (by RID or username)
    try:
        if user_input.isdigit():
            rid = int(user_input)
            log_debug(debug, f"[debug] Looking up RID {rid}...")
            lookup_resp = samr.hSamrLookupIdsInDomain(dce, domainHandle, [rid])
            add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
            if not lookup_resp['Names']['Element']:
                raise Exception(f"No user found with RID {rid}")
            username = safe_str(lookup_resp['Names']['Element'][0]['Data'])
        else:
            username = user_input
            log_debug(debug, f"[debug] Looking up username '{username}'...")
            lookup_resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
            add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
            rids = lookup_resp['RelativeIds']['Element']
            if not rids:
                raise Exception(f"User '{username}' not found")
    except Exception as e:
        raise Exception(f"User lookup failed: {str(e)}")

    log_debug(debug, f"[debug] Looking up user '{username}'...")
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) != SID_NAME_USER:
        raise Exception(f"User '{username}' not found")

    user_rid = extract_ndr_value(rids[0])
    userHandle = samr.hSamrOpenUser(dce, domainHandle, 0x0002011b, user_rid)['UserHandle']
    add_opnum_call(opnums_called, "SamrOpenUser")

    # Query user information and retrieve the 'All' dictionary
    try:
        add_opnum_call(opnums_called, "SamrQueryInformationUser2")
        response = samr.hSamrQueryInformationUser2(
            dce,
            userHandle,
            samr.USER_INFORMATION_CLASS.UserAllInformation
        )
        all_info = response['Buffer']['All']
    except Exception as e:
        log_debug(debug, f"[debug] UserAllInformation failed: {str(e)}, trying GeneralInformation2")
        response = samr.hSamrQueryInformationUser2(
            dce,
            userHandle,
            samr.USER_INFORMATION_CLASS.UserGeneralInformation
        )
        all_info = response['Buffer']['General']

    # Helper to decode numeric values if returned as bytes
    def decode_int(val):
        if isinstance(val, bytes):
            return int.from_bytes(val, byteorder='little')
        return val

    # Process UserAccountControl for flag evaluation
    uac_value = response['Buffer']['All']['UserAccountControl']
    uac_int = int(uac_value)

    if uac_int & 0x00004000:
        print("ACB_NOT_DELEGATED is set")
        delegated = False
    else:
        delegated = True

    if uac_int & 0x00010000:
        pre_auth = False
    else:
        pre_auth = True

    # Process PasswordExpired field
    pw_exp = all_info['PasswordExpired']
    pw_exp_int = decode_int(pw_exp)
    password_expired_bool = bool(pw_exp_int)
    last_logon_ft = decode_filetime(all_info['LastLogon'])
    last_logoff_ft = decode_filetime(all_info['LastLogoff'])
    pwd_last_set_ft = decode_filetime(all_info['PasswordLastSet'])
    acct_expires_ft = decode_filetime(all_info['AccountExpires'])
    pwd_can_change_ft = decode_filetime(all_info['PasswordCanChange'])
    pwd_must_change_ft = decode_filetime(all_info['PasswordMustChange'])
    account_disabled = bool(uac_int & samr.USER_ACCOUNT_DISABLED)
    smartcard_required = bool(uac_int & samr.USER_SMARTCARD_REQUIRED)
    password_never_expires = bool(uac_int & samr.USER_DONT_EXPIRE_PASSWORD)

    return {
        'rid': user_rid,
        'username': safe_str(all_info['UserName']),
        'full_name': safe_str(all_info['FullName']),
        'description': safe_str(all_info['AdminComment']),
        'last_logon': last_logon_ft,
        'last_logoff': last_logoff_ft,
        'logon_count': safe_str(all_info['LogonCount']),
        'password_last_set': pwd_last_set_ft,
        'password_can_change': pwd_can_change_ft,
        'password_force_change': pwd_must_change_ft,
        'password_expired': password_expired_bool,
        'password_never_expires': password_never_expires,
        'password_bad_count': safe_str(all_info['BadPasswordCount']),
        'account_expires': acct_expires_ft,
        'account_disabled': account_disabled,
        'home_directory': safe_str(all_info['HomeDirectory']),
        'home_drive': safe_str(all_info['HomeDirectoryDrive']),
        'script_path': safe_str(all_info['ScriptPath']),
        'profile_path': safe_str(all_info['ProfilePath']),
        'workstations': safe_str(all_info['WorkStations']),
        'usercomment': safe_str(all_info['UserComment']),
        'primary_gid': safe_str(all_info['PrimaryGroupId']),
        'user_account_control': safe_str(all_info['UserAccountControl']),
        'which_fields': safe_str(all_info['WhichFields']),
        'logon_hours': safe_str(all_info['LogonHours']),
        'country_code': safe_str(all_info['CountryCode']),
        'code_page': safe_str(all_info['CodePage']),
        'delegated': delegated,
        'pre_auth': pre_auth,
        'smartcard_required': smartcard_required,
    }


def get_local_group_details(dce, builtinHandle, alias_name, debug, opnums_called, primaryDomainHandle, primaryDomainSid):
    """
    Retrieve detailed information about a local alias (group) from the Builtin domain.
    This function looks up the alias by its name using the Builtin domain handle,
    opens the alias with ALIAS_LIST_MEMBERS access, retrieves its member list,
    resolves the member SIDs to usernames using the primary domain handle,
    and returns a dictionary with keys 'alias_name', 'rid', 'member_count', 'members',
    and 'primary_domain_sid'.

    :param dce: DCE/RPC connection object.
    :param builtinHandle: Handle to the Builtin domain.
    :param alias_name: The name of the alias (local group) to look up.
    :param debug: Boolean indicating whether debug messages should be printed.
    :param opnums_called: List tracking SAMR operations performed.
    :param primaryDomainHandle: Handle to the primary domain for SID resolution.
    :param primaryDomainSid: The SID of the primary domain as a string.
    :return: Dictionary containing alias details (alias name, RID, member count, members, primary domain SID).
    """
    # Lookup the alias by name using the Builtin domain handle
    lookupResp = samr.hSamrLookupNamesInDomain(dce, builtinHandle, [alias_name])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) != SID_NAME_ALIAS:
        raise Exception(f"Alias '{alias_name}' not found or not a valid alias.")
    alias_rid = extract_ndr_value(rids[0])

    # Open the alias with ALIAS_LIST_MEMBERS access
    desired_access = 0x00020004  # MAXIMUM_ALLOWED
    aliasHandle = samr.hSamrOpenAlias(dce, builtinHandle, desired_access, alias_rid)['AliasHandle']
    add_opnum_call(opnums_called, "SamrOpenAlias")

    # Retrieve the members
    membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInAlias")
    member_count = len(membersResp['Members']['Sids'])

    # Resolve each member SID using the primary domain handle
    members = []
    for sid in membersResp['Members']['Sids']:
        sid_str = sid['SidPointer'].formatCanonical()
        parts = sid_str.split('-')
        # The last part is the RID
        rid = parts[-1]
        try:
            add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
            lookupResp2 = samr.hSamrLookupIdsInDomain(dce, primaryDomainHandle, [int(rid)])
            if lookupResp2['Names']['Element']:
                username = safe_str(lookupResp2['Names']['Element'][0]['Data'])
                members.append((int(rid), username))
            else:
                members.append((int(rid), 'N/A'))
        except Exception as e:
            log_debug(debug, f"[debug] SID resolution failed for {sid_str}: {str(e)}")
            members.append((int(rid), 'N/A'))

    samr.hSamrCloseHandle(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    return {
        'alias_name': alias_name,
        'rid': alias_rid,
        'member_count': member_count,
        'members': members,
        'primary_domain_sid': primaryDomainSid
    }


def get_domain_group_details(dce, domainHandle, group_name, debug, opnums_called):
    """
    Retrieve detailed information about a domain group and resolve member usernames.

    This function looks up the group by its name in the given domain,
    opens the group with GROUP_LIST_MEMBERS access, retrieves the member list,
    resolves the member RIDs to usernames with an additional SAMR call,
    and returns a dictionary with the group name, RID, member count, and members list.

    :param dce: DCE/RPC connection object
    :param domainHandle: Handle to the domain obtained via SamrOpenDomain
    :param group_name: The name of the group to look up
    :param debug: Boolean for debug output
    :param opnums_called: List tracking SAMR operations performed
    :return: Dictionary with keys 'group_name', 'rid', 'member_count', and 'members'
    """
    # Lookup the group by name
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [group_name])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) not in (SID_NAME_GROUP, SID_NAME_WKN_GRP):
        raise Exception(f"Group '{group_name}' not found or not a valid domain group.")
    group_rid = extract_ndr_value(rids[0])

    # Open the group to retrieve members
    desired_access = 0x00000011
    groupHandle = samr.hSamrOpenGroup(dce, domainHandle, desired_access, group_rid)['GroupHandle']
    add_opnum_call(opnums_called, "SamrOpenGroup", desired_access)

    membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInGroup")
    member_count = len(membersResp['Members']['Members'])

    # Resolve member RIDs to usernames
    rids_list = []
    for ridEntry in membersResp['Members']['Members']:
        if isinstance(ridEntry, int):
            rids_list.append(ridEntry)
        elif hasattr(ridEntry, 'fields'):
            rids_list.append(extract_ndr_value(ridEntry))
        else:
            rids_list.append(extract_ndr_value(ridEntry['RelativeId']))

    members = []
    if rids_list:
        add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
        lookupResp2 = samr.hSamrLookupIdsInDomain(dce, domainHandle, rids_list)
        names = [safe_str(name['Data']) for name in lookupResp2['Names']['Element']]
        members = list(zip(rids_list, names))

    # Close the group handle
    samr.hSamrCloseHandle(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    return {
        'group_name': group_name,
        'rid': group_rid,
        'member_count': member_count,
        'members': members,
    }


def enumerate_display_info_local_groups(dce, builtinHandle, group_name, group_rid, debug, opnums_called):
    """
    Retrieve additional details for a local group (alias) from the Builtin domain.
    This function looks up the alias by its name using the Builtin domain handle,
    opens the alias with ALIAS_LIST_MEMBERS access, retrieves its member list,
    queries additional information via SamrQueryInformationAlias (e.g. description),
    and returns a dictionary with keys:
      'group_name', 'rid', 'member_count', and 'description'.

    :param dce: DCE/RPC connection object.
    :param builtinHandle: Handle to the Builtin domain.
    :param group_name: Name of the local group.
    :param group_rid: RID of the local group.
    :param debug: Boolean indicating whether debug output is enabled.
    :param opnums_called: List tracking SAMR operations performed.
    :return: Dictionary with local group details: name, RID, member count, and description.
    """
    # Open the alias with ALIAS_LIST_MEMBERS access
    desired_access = 0x0000000C
    aliasHandle = samr.hSamrOpenAlias(
        dce,
        builtinHandle,
        desired_access,
        group_rid
    )['AliasHandle']
    add_opnum_call(opnums_called, "SamrOpenAlias", desired_access)

    # Query additional alias information (e.g. AdminComment)
    try:
        add_opnum_call(opnums_called, "SamrQueryInformationAlias")
        aliasInfoResp = samr.hSamrQueryInformationAlias(dce, aliasHandle, 1)
        info = aliasInfoResp['Buffer']['General']
        try:
            desc_val = safe_str(info['AdminComment'])
        except Exception:
            desc_val = ""
    except Exception:
        desc_val = ""

    # Get members count
    membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInAlias")
    member_count = len(membersResp['Members']['Sids'])

    samr.hSamrCloseHandle(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    return {
        'group_name': group_name,
        'rid': group_rid,
        'member_count': member_count,
        'description': desc_val
    }


def enumerate_display_info_domain_groups(dce, domainHandle, group_name, group_rid, debug, opnums_called):
    """
    Retrieve additional details for a domain group.
    For example, count the number of members in the group and get its description.

    :param dce: DCE/RPC connection object.
    :param domainHandle: Handle to the domain.
    :param group_name: Name of the domain group.
    :param group_rid: RID of the domain group.
    :param debug: Boolean for enabling debug messages.
    :param opnums_called: List tracking SAMR operations performed.
    :return: Dictionary with domain group details: name, RID, member count, members, and description.
    """
    # Open the group to retrieve members
    actual_access = 0x00000011
    groupHandle = samr.hSamrOpenGroup(dce, domainHandle, actual_access, group_rid)['GroupHandle']
    add_opnum_call(opnums_called, "SamrOpenGroup", actual_access)
    membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInGroup")
    member_count = len(membersResp['Members']['Members'])
    # Resolve member RIDs to names
    rids_list = []
    for ridEntry in membersResp['Members']['Members']:
        if isinstance(ridEntry, int):
            rids_list.append(ridEntry)
        elif hasattr(ridEntry, 'fields'):
            rids_list.append(extract_ndr_value(ridEntry))
        else:
            rids_list.append(extract_ndr_value(ridEntry['RelativeId']))
    members = []
    if rids_list:
        add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
        lookupResp2 = samr.hSamrLookupIdsInDomain(dce, domainHandle, rids_list)
        names = [safe_str(name['Data']) for name in lookupResp2['Names']['Element']]
        members = list(zip(rids_list, names))

    # Query the group information to get the description.
    try:
        add_opnum_call(opnums_called, "SamrQueryInformationGroup")
        groupInfoResp = samr.hSamrQueryInformationGroup(
            dce,
            groupHandle,
            samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation
        )
        info = groupInfoResp['Buffer']['General']

        # Retrieve the description from AdminComment
        admin_comment = safe_str(info['AdminComment'])
        if not admin_comment:
            admin_comment = safe_str(info['Comment'])

        description = admin_comment

    except Exception as e:
        if debug:
            print(f"[debug] Could not query group information for {group_name}: {str(e)}")
        description = ""

    samr.hSamrCloseHandle(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    return {
        'group_name': group_name,
        'rid': group_rid,
        'member_count': member_count,
        'members': members,
        'description': description
    }


def get_computer_details(dce, domainHandle, computer_rid, debug, opnums_called):
    """
    Retrieve detailed computer information from SAMR using the computer's RID.
    Returns a dictionary with keys matching the display-info columns for computers.

    :param dce: DCE/RPC connection object.
    :param domainHandle: Handle to the domain.
    :param computer_rid: RID of the computer account.
    :param debug: Boolean for enabling debug messages.
    :param opnums_called: List tracking SAMR operations performed.
    :return: Dictionary containing computer details matching the display-info columns.
    """
    # SamrOpenUser for the computer account
    compHandle = None
    try:
        compHandleResp = samr.hSamrOpenUser(dce, domainHandle, 0x0002011B, computer_rid)
        compHandle = compHandleResp['UserHandle']
        add_opnum_call(opnums_called, "SamrOpenUser")

        # QueryInformationUser2 with UserAllInformation if possible
        try:
            add_opnum_call(opnums_called, "SamrQueryInformationUser2")
            response = samr.hSamrQueryInformationUser2(
                dce,
                compHandle,
                samr.USER_INFORMATION_CLASS.UserAllInformation
            )
            info = response['Buffer']['All']
        except Exception:
            # Fallback to UserGeneralInformation
            add_opnum_call(opnums_called, "SamrQueryInformationUser2")
            response = samr.hSamrQueryInformationUser2(
                dce,
                compHandle,
                samr.USER_INFORMATION_CLASS.UserGeneralInformation
            )

        info = response['Buffer']['All']
        uac_int = int(info['UserAccountControl'])

        if uac_int & 0x00004000:
            delegated = "Not Delegated"
        elif uac_int & 0x00040000:
            delegated = "Yes"
        elif uac_int & 0x00002000:
            delegated = "Yes"
        else:
            delegated = "No"

        trust_type = ("Workstation" if (uac_int & samr.USER_WORKSTATION_TRUST_ACCOUNT)
                      else "Server" if (uac_int & samr.USER_SERVER_TRUST_ACCOUNT)
        else "N/A")

        # Safely retrieve 'AdminComment' or 'Comment'
        try:
            desc_val = info['AdminComment']
        except KeyError:
            try:
                desc_val = info['Comment']
            except KeyError:
                desc_val = ''

        details = {
            'rid': computer_rid,
            'computer_name': safe_str(info['UserName']),
            'last_logon': decode_filetime(info['LastLogon']),
            'password_last_set': decode_filetime(info['PasswordLastSet']),
            'primary_group_id': safe_str(info['PrimaryGroupId']),
            'bad_password_count': safe_str(info['BadPasswordCount']),
            'logon_count': safe_str(info['LogonCount']),
            'trust_type': trust_type,
            'enabled': not bool(uac_int & samr.USER_ACCOUNT_DISABLED),
            'password_not_required': bool(uac_int & samr.USER_PASSWORD_NOT_REQUIRED),
            'password_never_expires': bool(uac_int & samr.USER_DONT_EXPIRE_PASSWORD),
            'delegation_status': delegated,
            'description': safe_str(desc_val),
        }
        return details

    finally:
        if compHandle is not None:
            samr.hSamrCloseHandle(dce, compHandle)
            add_opnum_call(opnums_called, "SamrCloseHandle")


def display_info(dce, serverHandle, info_type, debug, opnums_called):
    """
    Enumerate objects of a given type and return detailed information.

    :param dce: DCE/RPC connection object.
    :param serverHandle: Handle to the SAMR server.
    :param info_type: One of 'users', 'computers', 'local-groups', or 'domain-groups'.
    :param debug: Boolean for enabling debug messages.
    :param opnums_called: List tracking SAMR operations performed.
    :return: List of dictionaries with detailed information. For local and domain groups,
             a tuple (results, domainSid) may be returned.
    """
    results = []
    if info_type == 'users':
        # Get primary domain handle and enumerate users
        domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
        users = enumerate_users(dce, domainHandle, debug)
        add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")
        for username, rid in users:
            try:
                details = get_user_details(dce, domainHandle, username, debug, opnums_called)
                results.append(details)
            except Exception as e:
                results.append({'username': username, 'rid': rid, 'error': str(e)})
        # Close the domain handle after use
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    elif info_type == 'computers':
        # Open primary domain handle (same as for users)
        domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
        # Enumerate basic computer entries (each is a dict with at least 'rid' and 'computer_name')
        basic_computers = enumerate_computers(dce, domainHandle, debug)
        add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")
        detailed_computers = []
        for comp in basic_computers:
            rid = comp.get('rid')
            try:
                # This helper should mimic get_user_details but for computer objects
                details = get_computer_details(dce, domainHandle, rid, debug, opnums_called)
                detailed_computers.append(details)
            except Exception as e:
                detailed_computers.append({
                    'rid': rid,
                    'computer_name': comp.get('computer_name', 'N/A'),
                    'error': str(e)
                })
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")
        results = detailed_computers

    elif info_type == 'local-groups':
        # Use the Builtin domain to enumerate local groups (aliases)
        builtinHandle, builtinDomainName, domainSidString = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
        try:
            aliasResp = samr.hSamrEnumerateAliasesInDomain(dce, builtinHandle)
            add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
            aliases = aliasResp['Buffer']['Buffer'] or []
        except Exception as e:
            aliases = []
        results = []
        group_tuples = [(safe_str(alias['Name']), alias['RelativeId']) for alias in aliases]
        for group_name, group_rid in group_tuples:
            try:
                details = enumerate_display_info_local_groups(dce, builtinHandle, group_name, group_rid, debug, opnums_called)
                results.append(details)
            except Exception as e:
                results.append({'group_name': group_name, 'rid': group_rid, 'error': str(e)})
        samr.hSamrCloseHandle(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")
        return results, domainSidString

    elif info_type == 'domain-groups':
        # Get domain handle and SID
        domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
        # Get basic list of domain groups (each as (group_name, rid))
        basic_groups, did_aliases = enumerate_domain_groups(dce, domainHandle, debug)
        add_opnum_call(opnums_called, "SamrEnumerateGroupsInDomain")
        if did_aliases:
            add_opnum_call(opnums_called, "SamrEnumerateAliasesInSamServer")
        # For each group, get detailed info (including description)
        results = []
        for group_name, group_rid in basic_groups:
            detailed = enumerate_display_info_domain_groups(dce, domainHandle, group_name, group_rid, debug,
                                                            opnums_called)
            results.append(detailed)
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")
        # Return both results and domain SID
        return results, domainSid

    else:
        raise Exception(f"Invalid type parameter for display-info: {info_type}")
    return results


def get_lockout_policy(dce, domainHandle, debug, opnums_called):
    """
    Retrieve the domain lockout policy using SamrQueryInformationDomain2.

    :param dce: DCE/RPC connection object.
    :param domainHandle: Handle to the opened domain.
    :param debug: Boolean indicating debug output.
    :param opnums_called: List to track SAMR functions called.
    :return: Dictionary containing lockout policy details.
    """
    log_debug(debug, "[debug] Querying domain lockout policy...")
    add_opnum_call(opnums_called, "SamrQueryInformationDomain2")

    try:
        resp_lockout = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        )
        lockout_info = resp_lockout['Buffer']['Lockout']

        # Convert time intervals with special handling
        def ticks_to_days(ticks_obj):
            """Convert OLD_LARGE_INTEGER to days with Windows special value handling"""
            if not isinstance(ticks_obj, samr.OLD_LARGE_INTEGER):
                return 0

            # Handle "Never expire" special case (HighPart = 0x80000000)
            if ticks_obj['HighPart'] == -2147483648:  # 0x80000000 in signed int32
                return 0

            # Combine HighPart and LowPart into 64-bit integer
            ticks = (ticks_obj['HighPart'] << 32) | (ticks_obj['LowPart'] & 0xFFFFFFFF)

            # Handle negative values (two's complement)
            if ticks_obj['HighPart'] < 0:
                ticks = -((~ticks + 1) & 0xFFFFFFFFFFFFFFFF)

            seconds = abs(ticks) // 10000000  # 100ns -> seconds
            return seconds // 86400  # seconds -> days

        lockout_threshold = lockout_info['LockoutThreshold']
        lockout_duration = ticks_to_days(lockout_info['LockoutDuration'])
        lockout_window = ticks_to_days(lockout_info['LockoutObservationWindow'])

        return {
            'lockout_threshold': lockout_threshold,
            'lockout_duration': lockout_duration,
            'lockout_window': lockout_window
        }

    except Exception as e:
        if debug:
            print(f"[debug] Full error: {str(e)}")
        raise


def get_password_policy(dce, domainHandle, debug, opnums_called):
    """
    Retrieve the domain password policy using SamrQueryInformationDomain2.

    :param dce: DCE/RPC connection object.
    :param domainHandle: Handle to the opened domain.
    :param debug: Boolean indicating whether debug output is enabled.
    :param opnums_called: List tracking SAMR operations performed.
    :return: Dictionary containing password policy details (min length, max age, etc.).
    """
    log_debug(debug, "[debug] Querying domain password policy...")
    add_opnum_call(opnums_called, "SamrQueryInformationDomain2")
    try:
        resp = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        )
        password_info = resp['Buffer']['Password']

        resp_lockout = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        )
        lockout_info = resp_lockout['Buffer']['Lockout']

        def ticks_to_days(ticks_obj):
            if not isinstance(ticks_obj, samr.OLD_LARGE_INTEGER):
                return 0
            if ticks_obj['HighPart'] == -2147483648:
                return 0
            ticks = (ticks_obj['HighPart'] << 32) | (ticks_obj['LowPart'] & 0xFFFFFFFF)
            if ticks_obj['HighPart'] < 0:
                ticks = -((~ticks + 1) & 0xFFFFFFFFFFFFFFFF)
            seconds = abs(ticks) // 10000000
            return seconds // 86400

        max_age_days = ticks_to_days(password_info['MaxPasswordAge'])
        min_age_days = ticks_to_days(password_info['MinPasswordAge'])

        lockout_threshold = lockout_info['LockoutThreshold']
        lockout_duration = ticks_to_days(lockout_info['LockoutDuration'])
        lockout_window = ticks_to_days(lockout_info['LockoutObservationWindow'])

        # Retrieve the password properties flags from the PasswordProperties field.
        props = password_info['PasswordProperties']
        # (Assuming these constants exist in samr; if not, define them as needed.)
        pwd_complex = bool(props & samr.DOMAIN_PASSWORD_COMPLEX)
        no_anon     = bool(props & samr.DOMAIN_PASSWORD_NO_ANON_CHANGE)
        no_clrchg   = bool(props & samr.DOMAIN_PASSWORD_NO_CLEAR_CHANGE)
        lock_admins = bool(props & samr.DOMAIN_LOCKOUT_ADMINS)
        store_clr   = bool(props & samr.DOMAIN_PASSWORD_STORE_CLEARTEXT)
        refuse_chg  = bool(props & samr.DOMAIN_REFUSE_PASSWORD_CHANGE)

        pwd_props_flags = {
            'PwdComplex': yes_no(pwd_complex),
            'NoAnon':     yes_no(no_anon),
            'NoClrChg':   yes_no(no_clrchg),
            'LockAdmins': yes_no(lock_admins),
            'StoreClr':   yes_no(store_clr),
            'RefuseChg':  yes_no(refuse_chg),
        }

        return {
            'min_length': password_info['MinPasswordLength'],
            'history_length': password_info['PasswordHistoryLength'],
            'max_age_days': max_age_days,
            'min_age_days': min_age_days,
            'lockout_threshold': lockout_threshold,
            'lockout_duration': lockout_duration,
            'lockout_window': lockout_window,
            'pwd_properties_flags': pwd_props_flags
        }
    except Exception as e:
        if debug:
            print(f"[debug] Full error: {str(e)}")
        raise


def get_domain_info(dce, serverHandle, debug, opnums_called):
    """
    Retrieve basic domain information.

    :param dce: DCE/RPC connection object.
    :param serverHandle: Handle to the SAMR server.
    :param debug: Boolean for enabling debug output.
    :param opnums_called: List tracking SAMR operations performed.
    :return: Dictionary with domain details (domain SID, domain name, etc.).
    """
    def ticks_to_days(ticks_obj):
        if not isinstance(ticks_obj, samr.OLD_LARGE_INTEGER):
            return 0
        if ticks_obj['HighPart'] == -2147483648:
            return 0
        ticks = (ticks_obj['HighPart'] << 32) | (ticks_obj['LowPart'] & 0xFFFFFFFF)
        if ticks_obj['HighPart'] < 0:
            ticks = -((~ticks + 1) & 0xFFFFFFFFFFFFFFFF)
        return (abs(ticks) // 10000000) // 86400

    log_debug(debug, "[debug] Enumerating domains to get domain name...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
    add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on target.")
    domainName = safe_str(domains[0]['Name'])

    log_debug(debug, f"[debug] Looking up domain '{domainName}'...")
    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
    add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
    domainSid = lookupResp['DomainId']
    sidString = domainSid.formatCanonical()

    log_debug(debug, "[debug] Opening domain with MAXIMUM_ALLOWED access...")
    openDomResp = samr.hSamrOpenDomain(dce, serverHandle, 0x00000305, domainSid)
    add_opnum_call(opnums_called, "SamrOpenDomain", 0x00000305)
    domainHandle = openDomResp['DomainHandle']

    try:
        resp_general = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2
        )
        # Log the call for SamrQueryInformationDomain2 (OpNum 46)
        add_opnum_call(opnums_called, "SamrQueryInformationDomain2")
        general_info = resp_general['Buffer']['General2']

        resp_password = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        )
        add_opnum_call(opnums_called, "SamrQueryInformationDomain2")
        password_info = resp_password['Buffer']['Password']

        modified_struct = general_info.fields.get('DomainModifiedCount')
        modified_count = modified_struct.fields.get('LowPart', 0) if modified_struct is not None else 0

        return {
            'domain_sid': sidString,
            'domain_name': domainName,
            'oem_information': safe_str(general_info.fields.get('OemInformation', b'')),
            'modified_count': modified_count,
            'force_logoff_days': ticks_to_days(general_info.fields.get('ForceLogoff', 0)),
            'max_password_age_days': ticks_to_days(password_info.fields['MaxPasswordAge']),
            'min_password_age_days': ticks_to_days(password_info.fields['MinPasswordAge']),
            'lockout_threshold': safe_str(extract_ndr_value(general_info.fields.get('LockoutThreshold', 0))),
            'lockout_duration_days': ticks_to_days(general_info.fields['LockoutDuration']),
            'lockout_window_days': ticks_to_days(general_info.fields['LockoutObservationWindow']),
            'server_state': general_info.fields.get('DomainServerState', 0),
            'server_role': {2: "Backup", 3: "Primary"}.get(general_info.fields.get('DomainServerRole', 0), "Unknown"),
            'uas_compatible': general_info.fields.get('UasCompatibilityRequired', False),
            'num_users_total': general_info.fields.get('UserCount', 0),
            'num_global_groups': general_info.fields.get('GroupCount', 0),
            'num_aliases': general_info.fields.get('AliasCount', 0)
        }

    except Exception as e:
        raise Exception("Domain info query failed: " + safe_str(e))
    finally:
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")


def get_summary(dce, serverHandle, debug, opnums_called):
    """
    Generate a summary report for the domain including domain info, password policy,
    lockout policy, and counts of users, groups, and computers.

    :param dce: DCE/RPC connection object.
    :param serverHandle: Handle to the SAMR server.
    :param debug: Boolean for enabling debug output.
    :param opnums_called: List tracking SAMR operations performed.
    :return: List containing a single dictionary with summary details.
    """
    summary = {}

    # Get domain info (opens/closes its own handle)
    domain_info = get_domain_info(dce, serverHandle, debug, opnums_called)
    summary['domain_info'] = domain_info

    # Open primary domain handle for users, computers, domain groups, and policies
    domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
    try:
        # Enumerate users
        users = enumerate_users(dce, domainHandle, debug)
        # Log opnum for SamrEnumerateUsersInDomain (OpNum 13)
        add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")
        summary['total_users'] = len(users)

        # Enumerate computers
        computers = enumerate_computers(dce, domainHandle, debug)
        summary['total_computers'] = len(computers)

        # Enumerate domain groups
        domain_groups, _ = enumerate_domain_groups(dce, domainHandle, debug)
        # Log opnum for SamrEnumerateGroupsInDomain (OpNum 11)
        add_opnum_call(opnums_called, "SamrEnumerateGroupsInDomain")
        summary['total_domain_groups'] = len(domain_groups)

        # Get password policy
        password_policy = get_password_policy(dce, domainHandle, debug, opnums_called)
        summary['password_policy'] = password_policy

        # Get lockout policy
        lockout_policy = get_lockout_policy(dce, domainHandle, debug, opnums_called)
        summary['lockout_policy'] = lockout_policy
    finally:
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    # Open Builtin domain handle for local groups (aliases)
    builtinHandle, builtinName, builtinSid = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
    try:
        try:
            aliasResp = samr.hSamrEnumerateAliasesInDomain(dce, builtinHandle)
            # Log opnum for SamrEnumerateAliasesInDomain (OpNum 15)
            add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
            aliases = aliasResp['Buffer']['Buffer'] or []
        except Exception as e:
            aliases = []
        summary['total_local_groups'] = len(aliases)
    finally:
        samr.hSamrCloseHandle(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    return summary


def main():
    """
    Main function to parse command-line arguments, establish connection, perform enumeration,
    export data if requested, and handle any errors.

    :return: None
    """
    # Basic "help" check
    if len(sys.argv) > 1:
        # e.g. "python samr-enum.py help" or "python samr-enum.py help=whatever"
        first_arg = sys.argv[1].lower()
        if first_arg == "help" or "help" in first_arg:
            print_help()

    # If no args given, print usage
    if len(sys.argv) == 1:
        print("Usage:\n  python samr-enum.py target=dc1.domain-a.local"
              " username=user123 password=Password123 enumerate=domain-groups [domain=domain-b.local]"
              " [debug=true] [export=output.txt [format=txt|csv|json]] [auth=kerberos] [opnums=true]")
        sys.exit(1)

    args = parse_named_args(sys.argv)
    if args.get('help', 'false').lower() == 'true':
        print_help()

    enumeration = args.get('enumerate', 'domain-groups').lower()
    target = args.get('target', '')
    username = args.get('username', '')
    password = args.get('password', '')  # might be empty -> prompt
    debug = args.get('debug', 'false').lower() == 'true'
    export_file = args.get('export', '')
    export_format = args.get('format', 'txt').lower()
    auth_mode = args.get('auth', 'ntlm').lower()  # "kerberos" or "ntlm" default
    domain = args.get('domain', '')  # mandatory for Kerberos authentication
    opnums_param = args.get('opnums', 'false').lower() == 'true'

    # If password is empty, prompt user. getpass hides the input on CLI
    if password == '':
        password = getpass.getpass(prompt="Enter password (hidden): ")

    # If required parameters are missing, show usage
    if not target or not username:
        print("Usage:\n  python samr-enum.py enumerate=domain-groups target=dc1.domain-a.local"
              " username=user123 password=Password123 [group=MyGroup]"
              " [debug=true] [export=output.txt [format=txt|csv|json]] [domain=domain-b.local [auth=kerberos]] [opnums=true]")
        sys.exit(1)

    start_time = time.time()
    start_timestamp = datetime.now()
    print(f"Execution started at: {start_timestamp}")

    opnums_called = []
    dce = None
    serverHandle = None
    domainHandle = None
    domainSidString = ""
    enumerated_objects = []
    execution_status = "success"
    username = args.get('username', '')
    input_username = username

    try:
        dce, serverHandle = samr_connect(target, username, password, domain, debug, auth_mode)
        add_opnum_call(opnums_called, "SamrConnect")

        if enumeration == 'users':
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = enumerate_users(dce, domainHandle, debug)
            add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")

        elif enumeration == 'computers':
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = enumerate_computers(dce, domainHandle, debug)
            add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")

        elif enumeration == 'local-groups':
            # Use the Builtin domain to enumerate local groups (aliases) without extra query.
            domainHandle, domainName, domainSidString = get_builtin_domain_handle(dce, serverHandle, debug,
                                                                                  opnums_called)
            try:
                aliasResp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
                add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
                aliases = aliasResp['Buffer']['Buffer'] or []
            except Exception as e:
                aliases = []
            group_rids = [alias['RelativeId'] for alias in aliases]
            lookupResp2 = samr.hSamrLookupIdsInDomain(dce, domainHandle, group_rids)
            add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
            names = [safe_str(name['Data']) for name in lookupResp2['Names']['Element']]
            groups_result = list(zip(names, group_rids))
            enumerated_objects = groups_result
            samr.hSamrCloseHandle(dce, domainHandle)
            add_opnum_call(opnums_called, "SamrCloseHandle")

        elif enumeration == 'domain-groups':
            domainHandle, domainName, domainSidString = get_domain_handle(dce,
                                                                          serverHandle,
                                                                          debug, opnums_called)
            groups_result, did_aliases = enumerate_domain_groups(dce,
                                                                    domainHandle,
                                                                    debug)
            add_opnum_call(opnums_called, "SamrEnumerateGroupsInDomain")
            if did_aliases:
                add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
            enumerated_objects = groups_result

        elif enumeration == 'user-memberships-localgroups':
            user = args.get('user', '')
            if not user:
                raise Exception("Missing 'user=' argument")
            # Get primary domain SID for user SID construction
            domainHandle, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = list_user_local_memberships(dce, serverHandle, user, domainSidString, debug,
                                                             opnums_called)

        elif enumeration == 'user-memberships-domaingroups':
            user = args.get('user', '')
            if not user:
                raise Exception("Missing 'user=' argument")
            domainHandle, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = list_user_domain_memberships(dce, domainHandle, user, domainSidString, debug,
                                                              opnums_called)

        elif enumeration == 'account-details':
            user = args.get('user', '')
            if not user:
                raise Exception("Missing 'user=' argument")
            domainHandle, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            user_details = get_user_details(dce, domainHandle, user, debug, opnums_called)
            enumerated_objects = [user_details]

        elif enumeration == 'local-group-details':

            aliasName = args.get('group', '')

            if not aliasName:
                raise Exception("Missing 'group=' argument for local-group-details")
            # Use the Builtin domain to look up the alias
            builtinHandle, builtin_domain, _ = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
            # Get primary domain handle (and its SID) for resolving member SIDs
            primaryHandle, primaryDomainName, primaryDomainSid = get_domain_handle(dce, serverHandle, debug,
                                                                                   opnums_called)
            alias_details = get_local_group_details(dce, builtinHandle, aliasName, debug, opnums_called, primaryHandle,
                                                    primaryDomainSid)

            enumerated_objects = [alias_details]
            domainSidString = alias_details.get('primary_domain_sid', '')

        elif enumeration == 'domain-group-details':
            groupName = args.get('group', '')
            if not groupName:
                raise Exception("Missing 'group=' argument for domain-group-details")
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            group_details = get_domain_group_details(dce, domainHandle, groupName, debug, opnums_called)
            enumerated_objects = [group_details]

        elif enumeration == 'display-info':
            info_type = args.get('type', '').lower()
            if not info_type:
                raise Exception("Missing 'type=' argument for display-info")
            if info_type not in ['users', 'domain-groups', 'local-groups', 'computers']:
                raise Exception("Invalid 'type' for display-info.")
            if info_type in ['domain-groups', 'local-groups']:
                enumerated_objects, domainSidString = display_info(dce, serverHandle, info_type, debug, opnums_called)
            else:
                enumerated_objects = display_info(dce, serverHandle, info_type, debug, opnums_called)
                if info_type in ['users', 'computers']:
                    _, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)

        elif enumeration == 'summary':
            # Call get_summary() to get the aggregated domain summary info
            summary = get_summary(dce, serverHandle, debug, opnums_called)
            enumerated_objects = [summary]
            domainSidString = summary.get('domain_info', {}).get('domain_sid', '')

        else:
            raise Exception(f"Unknown enumeration: {enumeration}")

    except Exception as e:
        execution_status = f"error: {repr(e)}"

    finally:
        # SamrCloseHandle calls (no explicit Access Mask)
        for handle in [domainHandle, serverHandle]:
            if handle:
                try:
                    samr.hSamrCloseHandle(dce, handle)
                    add_opnum_call(opnums_called, "SamrCloseHandle")
                except:
                    pass
        if dce:
            dce.disconnect()

    duration = time.time() - start_time

    if enumerated_objects and execution_status == "success":

        if enumeration == 'users':
            max_length = max(
                len(str(obj[0])) for obj in enumerated_objects if isinstance(obj, tuple)
            ) if enumerated_objects else 25

            # Add +2 instead of +1 to shift "RID" a bit further right
            print("\nUsername".ljust(max_length + 5), "RID")
            print("-" * (max_length + 4), "----")
            for obj in enumerated_objects:
                if isinstance(obj, tuple) and len(obj) >= 2:
                    user_name = obj[0]
                    user_rid = obj[1]
                    # Also use max_length + 2 here
                    print(f"{user_name:<{max_length + 4}} {user_rid}")

        elif enumeration == 'computers':
            max_length = max(
                len(str(comp.get('computer_name', '')).rstrip('$'))
                for comp in enumerated_objects if isinstance(comp, dict)
            ) if enumerated_objects else 25
            print("\nName".ljust(max_length + 5), "RID")
            print("-" * (max_length + 4), "----")
            for comp in enumerated_objects:
                if isinstance(comp, dict):
                    comp_name = str(comp.get('computer_name', '')).rstrip('$')
                    comp_rid = comp.get('rid', 'N/A')
                    print(f"{comp_name:<{max_length + 4}} {comp_rid}")

        elif enumeration == 'user-memberships-domaingroups':
            max_length = max(len(str(obj[0])) for obj in enumerated_objects) if enumerated_objects else 25
            print(f"\n{'Member':<{max_length}} RID     Attributes")
            print("-" * (max_length + 30))
            for obj in enumerated_objects:
                if isinstance(obj, tuple) and len(obj) >= 3:
                    print(f"{obj[0]:<{max_length}} {obj[1]:<7} {decode_group_attributes(obj[2])}")

        elif enumeration == 'account-details':
            # Handle account details display
            details = enumerated_objects[0]
            print(f"\nAccount Details for {details.get('username', 'N/A')}:")
            print(f"  RID:                  {details.get('rid', 'N/A')}")
            print(f"  Username:             {details.get('username', 'N/A')}")
            print(f"  Full Name:            {details.get('full_name', 'N/A')}")
            print(f"  Description:          {details.get('description', 'N/A')}")
            print(f"  Last Logon:           {format_time(details.get('last_logon', 0))}")
            print(f"  Logon Count:          {details.get('logon_count', 'N/A')}")
            print(f"  Password Last Set:    {format_time(details.get('password_last_set', 0))}")
            print(f"  Password Can Chg:     {format_time(details.get('password_can_change', 0))}")
            print(f"  Password Force Chg:   {format_time(details.get('password_force_change', 0))}")
            print(f"  Password Expired:     {yes_no(details.get('password_expired', False))}")
            print(f"  Password Never Exp-s: {yes_no(details.get('password_never_expires', False))}")
            print(f"  Password Bad Count:   {details.get('password_bad_count', False)}")
            print(f"  Account Expires:      {format_time(details.get('account_expires', 0))}")
            print(f"  Account Disabled:     {yes_no(details.get('account_disabled', False))}")
            print(f"  Pre-Auth. Required:   {yes_no(details.get('pre_auth', False))}")
            print(f"  Delegation Allowed:   {yes_no(details.get('delegated', False))}")
            print(f"  Smartcard Required:   {yes_no(details.get('smartcard_required', False))}\n")

            print(f"  Primary Group ID:     {details.get('primary_gid', 'N/A')}")
            print(f"  Home Directory:       {details.get('home_directory', 'N/A')}")
            print(f"  Home Drive:           {details.get('home_drive', 'N/A')}")
            print(f"  Profile Path:         {details.get('profile_path', 'N/A')}")
            print(f"  Script Path:          {details.get('script_path', 'N/A')}")
            print(f"  Workstations:         {details.get('workstations', 'N/A')}")

        elif enumeration == 'local-group-details':
            details = enumerated_objects[0]
            print(f"\n{'-'*65}")
            print(f"{'Local Group Name:':<20}\t{details.get('alias_name', 'N/A')}")
            print(f"{'RID:':<20}\t{details.get('rid', 'N/A')}")
            print(f"{'Member Count:':<20}\t{details.get('member_count', 'N/A')}")
            print(f"{'Domain SID:':<20}\t{details.get('primary_domain_sid', 'N/A')}")
            members = details.get('members')
            if members:
                print(f"{'-'*65}")
                print(f"{'RID':<20}\t{'Username':<20}")
                print(f"{'-'*32}")
                for rid, username in members:
                    print(f"{rid:<20}\t{username:<20}")
            print()

        elif enumeration == 'domain-group-details':
            print(f"\n{'-'*65}")
            details = enumerated_objects[0]
            print(f"{'Domain Group Name:':<20}\t{details.get('group_name', 'N/A')}")
            print(f"{'RID:':<20}\t{details.get('rid', 'N/A')}")
            print(f"{'Member Count:':<20}\t{details.get('member_count', 'N/A')}")
            members = details.get('members')
            if members:
                print(f"{'-' * 65}")
                print(f"{'RID':<20}\t{'Username':<20}")
                print(f"{'-' * 32}")
                for rid, username in members:
                    print(f"{rid:<20}\t{username:<20}")
            print()

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'domain-groups':
            # Define columns: RID, MemCnt, Name, Description
            col_order = ["RID", "MemCnt", "Name", "Description"]
            col_widths = {"RID": 6, "MemCnt": 7, "Name": 30, "Description": 40}
            header_line = (f"{'RID':<{col_widths['RID']}} "
                           f"{'MemCnt':<{col_widths['MemCnt']}} "
                           f"{'Name':<{col_widths['Name']}} "
                           f"{'Description':<{col_widths['Description']}}")
            print("\n" + header_line)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            for obj in enumerated_objects:
                # Use safe_str for string fields and truncate the description if too long.
                rid = str(obj.get('rid', 'N/A'))
                memcnt = str(obj.get('member_count', 'N/A'))
                name = safe_str(obj.get('group_name', 'N/A'))
                desc = safe_str(obj.get('description', ''))
                if len(desc) > 40:
                    desc = desc[:37] + "..."
                row = (f"{rid:<{col_widths['RID']}} "
                       f"{memcnt:<{col_widths['MemCnt']}} "
                       f"{name:<{col_widths['Name']}} "
                       f"{desc:<{col_widths['Description']}}")
                print(row)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            print(header_line)
            print()

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'users':
            # Helper to convert a timestamp to a short date string
            def format_date(time_str):
                if time_str == 'Never' or not time_str:
                    return 'Never'
                try:
                    return time_str.split(" ")[0].replace('-', '.')
                except Exception:
                    return time_str

            # Define column order and widths (with Username and Full Name moved to the end)
            col_order = ["RID", "Last Logon", "PwdSet", "PwdNE", "PwdExp", "ForceChg", "AccDis",
                         "PreAuth", "Delg", "BadCnt", "Username", "Full Name"]
            col_widths = {
                "RID": 8,
                "Last Logon": 12,
                "PwdSet": 10,
                "PwdNE": 10,
                "PwdExp": 10,
                "ForceChg": 10,
                "AccDis": 10,
                "PreAuth": 10,
                "Delg": 8,
                "BadCnt": 10,
                "Username": 15,
                "Full Name": 20
            }
            # Build header string
            header = ""
            for col in col_order:
                header += f"{col:<{col_widths[col]}} "
            print()
            print(header)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            for obj in enumerated_objects:
                if 'error' in obj:
                    print(f"{obj.get('username', 'N/A')} - ERROR: {obj['error']}")
                else:
                    rid = str(obj.get('rid', 'N/A'))
                    last_logon = format_date(format_time(obj.get('last_logon', 0)))
                    pwd_set = format_date(format_time(obj.get('password_last_set', 0)))
                    pwd_nexp = "Yes" if obj.get('password_never_expires', False) else "No"
                    pwd_exp = "Yes" if obj.get('password_expired', False) else "No"
                    pwd_fchg = format_date(format_time(obj.get('password_force_change', 0)))
                    acc_dis = "Yes" if obj.get('account_disabled', False) else "No"
                    pre_auth = "Yes" if obj.get('pre_auth', False) else "No"
                    delegated = "Yes" if obj.get('delegated', False) else "No"
                    pwd_bad = str(obj.get('password_bad_count', 'N/A'))
                    username_val = obj.get('username', 'N/A')
                    full_name = obj.get('full_name', 'N/A')
                    row = (f"{rid:<{col_widths['RID']}} "
                           f"{last_logon:<{col_widths['Last Logon']}} "
                           f"{pwd_set:<{col_widths['PwdSet']}} "
                           f"{pwd_nexp:<{col_widths['PwdNE']}} "
                           f"{pwd_exp:<{col_widths['PwdExp']}} "
                           f"{pwd_fchg:<{col_widths['ForceChg']}} "
                           f"{acc_dis:<{col_widths['AccDis']}} "
                           f"{pre_auth:<{col_widths['PreAuth']}} "
                           f"{delegated:<{col_widths['Delg']}} "
                           f"{pwd_bad:<{col_widths['BadCnt']}} "
                           f"{username_val:<{col_widths['Username']}} "
                           f"{full_name:<{col_widths['Full Name']}}")
                    print(row)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            print(header)
            print()

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'computers':
            def format_date(time_str):
                """
                Convert a time string in 'YYYY-MM-DD HH:MM:SS' format to 'YYYY.MM.DD'.
                If the input is 'Never' or invalid, return it as is.
                """
                if time_str == 'Never' or not time_str:
                    return 'Never'
                try:
                    return time_str.split(" ")[0].replace('-', '.')
                except Exception:
                    return time_str

            # Define the table columns and widths
            col_order = [
                "RID", "Name", "Logons", "LastLogon", "PwdLastSet",
                "BadPwdCnt", "PID", "Type",
                "Enabled", "PwdNReq", "PwdNExp", "Deleg", "Description"
            ]
            col_widths = {
                "RID": 6,
                "Name": 18,
                "Logons": 6,
                "LastLogon": 11,
                "PwdLastSet": 11,
                "BadPwdCnt": 9,
                "PID": 4,
                "Type": 14,
                "Enabled": 8,
                "PwdNReq": 9,
                "PwdNExp": 8,
                "Deleg": 6,
                "Description": 14
            }
            # Print header row
            header = ""
            for col in col_order:
                header += f"{col:<{col_widths[col]}} "
            print("\n" + header)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            # Print each computer record
            for obj in enumerated_objects:
                if 'error' in obj:
                    print(f"{obj.get('computer_name', 'N/A'):<{col_widths['Name']}} - ERROR: {obj['error']}")
                else:
                    rid = str(obj.get('rid', 'N/A'))
                    comp_name = str(obj.get('computer_name', 'N/A')).rstrip('$')
                    # Assume you have a format_time() function similar to the user branch,
                    # and a helper format_date() to shorten the timestamp.
                    last_logon = format_date(format_time(obj.get('last_logon', 0)))
                    pwd_last_set = format_date(format_time(obj.get('password_last_set', 0)))
                    prim_grp_id = str(obj.get('primary_group_id', 'N/A'))
                    bad_pwd_count = str(obj.get('bad_password_count', 'N/A'))
                    logon_count = str(obj.get('logon_count', 'N/A'))
                    trust_type = obj.get('trust_type', 'N/A')
                    enabled = "Yes" if obj.get('enabled', False) else "No"
                    pwd_not_req = "Yes" if obj.get('password_not_required', False) else "No"
                    pwd_never_exp = "Yes" if obj.get('password_never_expires', False) else "No"
                    deleg_status = obj.get('delegation_status', 'N/A')
                    desc = obj.get('description', 'N/A')
                    row = (
                        f"{rid:<{col_widths['RID']}} "
                        f"{comp_name:<{col_widths['Name']}} "
                        f"{logon_count:<{col_widths['Logons']}} "
                        f"{last_logon:<{col_widths['LastLogon']}} "
                        f"{pwd_last_set:<{col_widths['PwdLastSet']}} "
                        f"{bad_pwd_count:<{col_widths['BadPwdCnt']}} "
                        f"{prim_grp_id:<{col_widths['PID']}} "
                        f"{trust_type:<{col_widths['Type']}} "
                        f"{enabled:<{col_widths['Enabled']}} "
                        f"{pwd_not_req:<{col_widths['PwdNReq']}} "
                        f"{pwd_never_exp:<{col_widths['PwdNExp']}} "
                        f"{deleg_status:<{col_widths['Deleg']}} "
                        f"{desc:<{col_widths['Description']}}"
                    )
                    print(row)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            print(header)
            print()

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'local-groups':
            # Define the column order and fixed widths for local groups
            col_order = ["RID", "MemCnt", "Name", "Description"]
            col_widths = {
                "RID": 4,
                "MemCnt": 6,
                "Name": 50,
                "Description": 40
            }
            # Build and print the header row
            header = ""
            for col in col_order:
                header += f"{col:<{col_widths[col]}} "
            print("\n" + header)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            # Print each local group record
            for obj in enumerated_objects:
                if 'error' in obj:
                    print(f"{obj.get('group_name', 'N/A'):<{col_widths['Name']}} - ERROR: {obj['error']}")
                else:
                    rid = str(obj.get('rid', 'N/A'))
                    name = obj.get('group_name', 'N/A')
                    members = str(obj.get('member_count', 'N/A'))
                    description = obj.get('description', 'N/A')
                    row = (f"{rid:<{col_widths['RID']}} "
                           f"{members:<{col_widths['MemCnt']}} "
                           f"{name:<{col_widths['Name']}} "
                           f"{description:<{col_widths['Description']}}")
                    print(row)
            print("-" * (sum(col_widths.values()) + len(col_order)))
            print(header)
            print()

        elif enumeration == 'display-info':
            info_type = args.get('type', '').lower()
            if not info_type:
                raise Exception("Missing 'type=' argument for display-info")
            if info_type not in ['users', 'domain-groups', 'local-groups', 'computers']:
                raise Exception("Invalid 'type' for display-info.")
            if info_type in ['domain-groups', 'local-groups']:
                enumerated_objects, domainSidString = display_info(dce, serverHandle, info_type, debug, opnums_called)
            else:
                enumerated_objects = display_info(dce, serverHandle, info_type, debug, opnums_called)

        elif enumeration == 'summary':
            # We assume enumerated_objects[0] is the summary dictionary
            summary = enumerated_objects[0]
            domain_info = summary.get('domain_info', {})
            print("\nDomain Information:")
            print(f"  Domain SID:                  {domain_info.get('domain_sid', 'N/A')}")
            print(f"  Domain Name:                 {domain_info.get('domain_name', 'N/A')}")
            print(f"  UAS Compatible:              {yes_no(domain_info.get('uas_compatible', False))}")
            print()
            print("Account Lockout Settings:")
            print(f"  Lockout Threshold:           {domain_info.get('lockout_threshold', 'N/A')}")
            print(f"  Lockout Duration (days):     {domain_info.get('lockout_duration_days', 'N/A')}")
            print(f"  Lockout Window (days):       {domain_info.get('lockout_window_days', 'N/A')}")
            print(f"  Force Logoff (days):         {domain_info.get('force_logoff_days', 'N/A')}")
            print()
            print("Password Policy:")
            print(f"  Minimum Password Length:     {domain_info.get('min_password_length', 'N/A')}")
            print(f"  Minimum Password Age (days): {domain_info.get('min_password_age_days', 'N/A')}")
            print(f"  Maximum Password Age (days): {domain_info.get('max_password_age_days', 'N/A')}")
            print(f"  Password History Length:     {domain_info.get('password_history_length', 'N/A')}")
            print(f"  Password Properties:")
            pp = summary.get('password_policy', {})
            flags = pp.get('pwd_properties_flags', {})
            for flag, val in flags.items():
                print(f"    {flag:<26} {val}")
            print()
            print(f"Total Users:                   {summary.get('total_users', 'N/A')}")
            print(f"Total Computers:               {summary.get('total_computers', 'N/A')}")
            print(f"Total Domain Groups:           {summary.get('total_domain_groups', 'N/A')}")
            print(f"Total Local Groups:            {summary.get('total_local_groups', 'N/A')}")
            print()

        else:
            # Handle regular enumerations (users/groups/computers)
            if isinstance(enumerated_objects[0], dict):
                max_length = max(
                    len(str(obj.get('username', 'N/A'))) for obj in enumerated_objects) if enumerated_objects else 25
                print(f"\n{'Username':<{max_length}} Details")
                print("-" * (max_length + 15))
                for obj in enumerated_objects:
                    if 'error' in obj:
                        print(f"{obj.get('username', 'N/A'):<{max_length}} ERROR: {obj['error']}")
                    else:
                        print(f"{obj.get('username', 'N/A'):<{max_length}} {obj.get('rid', 'N/A')}")
            else:
                max_length = max(len(str(obj[0])) for obj in enumerated_objects) if enumerated_objects else 25
                print(f"\n{'Member':<{max_length}} RID")
                print("-" * (max_length + 15))
                for obj in enumerated_objects:
                    if isinstance(obj, tuple) and len(obj) >= 2:
                        print(f"{obj[0]:<{max_length}} {obj[1]}")

    print("================================================================")
    print(f"{'Execution time:':<20}\t{duration:.2f} seconds")
    print(f"{'Destination target:':<20}\t{target}")
    print(f"{'Domain SID:':<20}\t{domainSidString}")
    print(f"{'Account:':<20}\t{input_username}")
    print(f"{'Enumerate:':<20}\t{enumeration}")
    print(f"{'Authentication:':<20}\t{auth_mode.upper()}")
    print(f"{'Execution status:':<20}\t{execution_status}")
    print(f"{'Number of objects:':<20}\t{len(enumerated_objects) if execution_status == 'success' else 0}")
    if opnums_param and opnums_called:
        print("OpNums called:")
        # Print a header
        print("  Name".ljust(35), "OpNum".ljust(6), "Access Mask")
        print("-" * 55)

        for item in opnums_called:
            name_str = item
            opnum_str = "--"
            mask_str = "--"

            paren_idx = item.find("(OpNum ")
            if paren_idx != -1:
                # Extract the function name from the front
                name_str = item[:paren_idx].strip()
                # Grab the substring inside the parentheses, e.g. "OpNum 0, Access Mask: 0x00000031)"
                inside = item[paren_idx:].strip("()")  # e.g. "OpNum 0, Access Mask: 0x00000031"
                # Split by commas (or do more robust parsing if needed)
                parts = inside.split(",")
                if parts:
                    # First part should be "OpNum X"
                    first = parts[0].strip()
                    # e.g. first == "OpNum 0"
                    if first.startswith("OpNum "):
                        opnum_str = first[len("OpNum "):].strip()

                if len(parts) > 1:
                    # Possibly "Access Mask: 0x00000031"
                    second = parts[1].strip()
                    if second.startswith("Access Mask:"):
                        mask_str = second[len("Access Mask:"):].strip()

            # Print each line, adjusting spacing
            print("  " + name_str.ljust(33), opnum_str.ljust(5), mask_str)
    print("================================================================")

    # Optionally export data
    if export_file and execution_status == "success" and enumerated_objects:
        export_data(export_file, export_format, enumerated_objects)


if __name__ == "__main__":
    main()
