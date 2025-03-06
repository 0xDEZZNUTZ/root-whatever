#!/usr/bin/env python3

import argparse
import sys
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.nmb import NetBIOSError

class SMBEnumerator:
    def __init__(self, target, port=445, domain="", username="", password="", anonymous=False):
        self.target = target
        self.port = port
        self.domain = domain
        self.username = username
        self.password = password
        self.anonymous = anonymous
        self.conn = None
    
    def connect(self):
        """Establish SMB connection to target"""
        try:
            self.conn = SMBConnection(self.target, self.target, timeout=5)
            
            if self.anonymous:
                print("[+] Attempting anonymous login")
                self.conn.login("", "")
            else:
                print(f"[+] Attempting login with {self.domain}\\{self.username}:{self.password}")
                self.conn.login(self.username, self.password, self.domain)
                
            print(f"[+] Successfully authenticated to {self.target}")
            print(f"[+] Server OS: {self.conn.getServerOS()}")
            print(f"[+] Server Hostname: {self.conn.getServerName()}")
            return True
            
        except NetBIOSError:
            print(f"[-] Failed to connect to {self.target}:{self.port}. Port might be closed.")
            return False
        except SessionError as e:
            print(f"[-] Authentication failed: {str(e)}")
            return False
        except Exception as e:
            print(f"[-] Error: {str(e)}")
            return False
    
    def check_eternalblue(self):
        """Check if target is potentially vulnerable to EternalBlue (MS17-010)"""
        from impacket.ImpactPacket import ImpactPacketException
        
        print("\n[+] Checking for EternalBlue vulnerability (MS17-010)...")
        try:
            # Try to force SMBv1 and see if it succeeds
            orig_dialect = self.conn.getDialect()
            
            # Create new connection with SMBv1 only
            temp_conn = SMBConnection(self.target, self.target, preferredDialect=SMB_DIALECT)
            
            if self.anonymous:
                temp_conn.login("", "")
            else:
                temp_conn.login(self.username, self.password, self.domain)
                
            # Check OS version
            os_version = temp_conn.getServerOS()
            
            # Windows versions likely to be vulnerable if SMBv1 is enabled
            vulnerable_versions = ["Windows 7", "Windows Server 2008", "Windows Vista", "Windows Server 2003", "Windows XP"]
            
            potential_risk = any(ver in os_version for ver in vulnerable_versions)
            
            if potential_risk:
                print(f"[!] WARNING: Target is running {os_version} with SMBv1 enabled")
                print(f"[!] System is potentially vulnerable to EternalBlue (MS17-010)")
                print(f"[!] Further verification required with specialized tools")
                return "Potentially Vulnerable"
            else:
                print(f"[+] Target is running {os_version} with SMBv1 enabled")
                print(f"[+] System is likely patched or not vulnerable to EternalBlue")
                return "Likely Not Vulnerable"
                
        except ImpactPacketException as e:
            if "SMBv1" in str(e):
                print("[+] SMBv1 is disabled on target")
                print("[+] System is likely not vulnerable to EternalBlue")
                return "Not Vulnerable - SMBv1 Disabled"
            else:
                print(f"[-] Error checking EternalBlue: {str(e)}")
                return "Check Failed"
        except Exception as e:
            print(f"[-] Error checking EternalBlue: {str(e)}")
            return "Check Failed"
    
    def enum_shares(self):
        """Enumerate available shares"""
        if not self.conn:
            return None
            
        print("\n[+] Enumerating shares:")
        try:
            shares = self.conn.listShares()
            
            if not shares:
                print("[-] No shares available or accessible")
                return None
                
            results = []
            for share in shares:
                share_name = share['shi1_netname'][:-1]  # Remove null byte
                share_remark = share['shi1_remark'][:-1] if share['shi1_remark'] else ""
                share_type = share['shi1_type']
                
                share_type_str = "Unknown"
                if share_type == 0: share_type_str = "Disk"
                elif share_type == 1: share_type_str = "Print Queue"
                elif share_type == 2: share_type_str = "Device"
                elif share_type == 3: share_type_str = "IPC"
                
                print(f"    Share: {share_name}")
                print(f"    Type: {share_type_str}")
                print(f"    Comment: {share_remark}")
                print(f"    ------------------------------")
                
                # Test accessibility by trying to list files
                try:
                    file_list = self.conn.listPath(share_name, "*")
                    print(f"    [+] Access: READ")
                    results.append({
                        'name': share_name,
                        'type': share_type_str,
                        'comment': share_remark,
                        'access': 'READ'
                    })
                except:
                    print(f"    [-] Access: NO ACCESS")
                    results.append({
                        'name': share_name,
                        'type': share_type_str,
                        'comment': share_remark,
                        'access': 'NO ACCESS'
                    })
                print("")
                
            return results
                
        except Exception as e:
            print(f"[-] Error listing shares: {str(e)}")
            return None
    
    def enum_users(self):
        """Enumerate users using SAMR protocol"""
        if not self.conn:
            return None
            
        try:
            from impacket.dcerpc.v5 import transport, samr
            
            print("\n[+] Enumerating users:")
            
            # Set up RPC connection over SMB
            rpctransport = transport.SMBTransport(self.target, self.port, r'\samr', username=self.username, password=self.password, domain=self.domain)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            # Open a handle to the SAMR service
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']
            
            # Enumerate domains
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp['Buffer']['Buffer']
            
            users = []
            
            # For each domain
            for domain in domains:
                domain_name = domain['Name']
                print(f"\n[+] Domain: {domain_name}")
                
                # Get domain handle
                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp['DomainId']
                resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
                domain_handle = resp['DomainHandle']
                
                # Enumerate users
                status = STATUS_MORE_ENTRIES = 0x00000105
                enumerationContext = 0
                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, 
                                                             enumerationContext=enumerationContext,
                                                             userAccountControl=samr.USER_NORMAL_ACCOUNT)
                        status = resp['ErrorCode']
                    except Exception as e:
                        print(f"[-] Error: {str(e)}")
                        break
                        
                    if resp['Count'] > 0:
                        for user in resp['Buffer']['Buffer']:
                            user_name = user['Name']
                            user_rid = user['RelativeId']
                            
                            # Get more user details
                            resp = samr.hSamrOpenUser(dce, domain_handle, userId=user_rid)
                            user_handle = resp['UserHandle']
                            resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
                            user_info = resp['Buffer']['All']
                            
                            account_enabled = (user_info['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED) == 0
                            
                            print(f"    User: {user_name}")
                            print(f"    RID: {user_rid}")
                            print(f"    Enabled: {'Yes' if account_enabled else 'No'}")
                            print(f"    ------------------------------")
                            
                            users.append({
                                'name': user_name,
                                'rid': user_rid,
                                'enabled': account_enabled,
                                'domain': domain_name
                            })
                            
                            # Close user handle
                            samr.hSamrCloseHandle(dce, user_handle)
                            
                    enumerationContext = resp['EnumerationContext']
                
                # Close domain handle
                samr.hSamrCloseHandle(dce, domain_handle)
            
            # Close server handle
            samr.hSamrCloseHandle(dce, server_handle)
            
            return users
            
        except Exception as e:
            print(f"[-] Error enumerating users: {str(e)}")
            return None
    
    def enum_groups(self):
        """Enumerate groups using SAMR protocol"""
        if not self.conn:
            return None
        
        try:
            from impacket.dcerpc.v5 import transport, samr
            
            print("\n[+] Enumerating groups:")
            
            # Set up RPC connection over SMB
            rpctransport = transport.SMBTransport(self.target, self.port, r'\samr', username=self.username, password=self.password, domain=self.domain)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            # Open a handle to the SAMR service
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']
            
            # Enumerate domains
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp['Buffer']['Buffer']
            
            groups = []
            
            # For each domain
            for domain in domains:
                domain_name = domain['Name']
                print(f"\n[+] Domain: {domain_name}")
                
                # Get domain handle
                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp['DomainId']
                resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
                domain_handle = resp['DomainHandle']
                
                # Enumerate groups
                status = STATUS_MORE_ENTRIES = 0x00000105
                enumerationContext = 0
                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateGroupsInDomain(dce, domain_handle, 
                                                              enumerationContext=enumerationContext)
                        status = resp['ErrorCode']
                    except Exception as e:
                        print(f"[-] Error: {str(e)}")
                        break
                        
                    if resp['Count'] > 0:
                        for group in resp['Buffer']['Buffer']:
                            group_name = group['Name']
                            group_rid = group['RelativeId']
                            
                            # Open group handle to get more details
                            resp = samr.hSamrOpenGroup(dce, domain_handle, groupId=group_rid)
                            group_handle = resp['GroupHandle']
                            
                            # Get group attributes
                            resp = samr.hSamrQueryInformationGroup(dce, group_handle, samr.GROUP_INFORMATION_CLASS.GroupAllInformation)
                            group_info = resp['Buffer']['All']
                            
                            print(f"    Group: {group_name}")
                            print(f"    RID: {group_rid}")
                            print(f"    Attributes: {group_info.get('Attributes', 'N/A')}")
                            print(f"    ------------------------------")
                            
                            groups.append({
                                'name': group_name,
                                'rid': group_rid,
                                'domain': domain_name,
                                'attributes': group_info.get('Attributes', 'N/A')
                            })
                            
                            # Close group handle
                            samr.hSamrCloseHandle(dce, group_handle)
                            
                    enumerationContext = resp['EnumerationContext']
                
                # Close domain handle
                samr.hSamrCloseHandle(dce, domain_handle)
            
            # Close server handle
            samr.hSamrCloseHandle(dce, server_handle)
            
            return groups
            
        except Exception as e:
            print(f"[-] Error enumerating groups: {str(e)}")
            return None

    def enum_permissions(self, share_name):
        """Enumerate permissions on a specific share"""
        if not self.conn:
            return None
            
        print(f"\n[+] Enumerating permissions for share: {share_name}")
        
        try:
            # Try to list all files and directories recursively on the share
            def list_path_recursive(path, depth=0):
                try:
                    files = self.conn.listPath(share_name, path)
                    
                    for file in files:
                        if file.get_longname() in ['.', '..']:
                            continue
                            
                        file_name = file.get_longname()
                        file_path = path + '\\' + file_name if path != '' else file_name
                        
                        # Get file attributes
                        is_directory = file.is_directory()
                        file_size = file.get_filesize()
                        last_write_time = file.get_mtime_str()
                        
                        # Print with indentation based on depth
                        indent = '    ' * (depth + 1)
                        print(f"{indent}{'[DIR]' if is_directory else '[FILE]'} {file_name}")
                        print(f"{indent}Path: {file_path}")
                        print(f"{indent}Size: {file_size} bytes")
                        print(f"{indent}Last Modified: {last_write_time}")
                        
                        # Check if we can read the file
                        if not is_directory:
                            try:
                                self.conn.getFile(share_name, file_path, None, 1)  # Try to read 1 byte
                                print(f"{indent}Read Access: Yes")
                            except:
                                print(f"{indent}Read Access: No")
                                
                            # Check if we can write to the file
                            try:
                                # Create a temporary file next to this one
                                temp_path = file_path + '.tmp'
                                self.conn.putFile(share_name, temp_path, b'test')
                                print(f"{indent}Write Access: Yes")
                                # Delete the temp file
                                self.conn.deleteFile(share_name, temp_path)
                            except:
                                print(f"{indent}Write Access: No")
                        
                        print(f"{indent}------------------------------")
                        
                        # Recursively list directories, but limit depth to avoid getting stuck
                        if is_directory and depth < 2:
                            list_path_recursive(file_path, depth + 1)
                            
                except Exception as e:
                    print(f"    [-] Error listing path {path}: {str(e)}")
            
            # Start recursive listing from root
            list_path_recursive('')
            
        except Exception as e:
            print(f"[-] Error enumerating permissions: {str(e)}")
            return None
            
    def disconnect(self):
        """Disconnect SMB connection"""
        if self.conn:
            self.conn.close()
            print("[+] SMB connection closed")

def main():
    parser = argparse.ArgumentParser(description="SMB Enumeration Tool")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--port", type=int, default=445, help="SMB port (default: 445)")
    parser.add_argument("-d", "--domain", default="", help="Domain name")
    parser.add_argument("-u", "--username", default="", help="Username")
    parser.add_argument("-P", "--password", default="", help="Password")
    parser.add_argument("-a", "--anonymous", action="store_true", help="Try anonymous login")
    parser.add_argument("-s", "--shares", action="store_true", help="Enumerate shares")
    parser.add_argument("--users", action="store_true", help="Enumerate users")
    parser.add_argument("--permissions", metavar="SHARE", help="Check permissions on a specific share")
    parser.add_argument("--vulns", action="store_true", help="Check for common vulnerabilities")
    parser.add_argument("--all", action="store_true", help="Run all enumeration checks")
    parser.add_argument("--groups", action="store_true", help="Enumerate groups")
    
    args = parser.parse_args()
    
    # Create SMB enumerator object
    smb = SMBEnumerator(
        args.target, 
        port=args.port,
        domain=args.domain,
        username=args.username,
        password=args.password,
        anonymous=args.anonymous
    )
    
    # Connect to target
    if not smb.connect():
        sys.exit(1)
    
    # Run requested enumeration operations
    if args.shares or args.all:
        smb.enum_shares()
        
    if args.users or args.all:
        smb.enum_users()
        
    if args.permissions:
        smb.enum_permissions(args.permissions)
        
    if args.vulns or args.all:
        smb.check_eternalblue()
        
    if args.groups or args.all:
        smb.enum_groups()
        
    # If no specific enumeration was requested, just list shares
    if not (args.shares or args.users or args.permissions or args.vulns or args.groups or args.all):
        smb.enum_shares()
    
    # Disconnect
    smb.disconnect()

if __name__ == "__main__":
    print("""
 ___ __  __ ___    ___ _  _ _   _ __  __ 
/ __|  \/  | _ )  | __| \| | | | |  \/  |
\__ \ |\/| | _ \  | _|| .` | |_| | |\/| |
|___/_|  |_|___/  |___|_|\_|\___/|_|  |_|
                                         
""")
    print("\n[!] IMPORTANT LEGAL NOTICE [!]")
    print("SMB Enumeration Tool created by Nutzh")
    print("""
* This tool is provided strictly for:
  - Authorized penetration testing
  - Security research with explicit permission
  - Educational purposes on approved systems

By proceeding, you acknowledge that:
- You have proper authorization for this scan
- You understand the legal implications
- You accept full responsibility for your actions
""")
    main()