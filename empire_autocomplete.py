"""this is auto-generated for EmpireAPIWrapper"""

class management(object):
	class mailraider_disable_security(object):
		"""This function checks for the ObjectModelGuard, PromptOOMSend, and AdminSecurityMode registry keys for Outlook security. This function must be run in an administrative context in order to set the values for the registry keys.
		"""

		path = 'powershell/management/mailraider/disable_security'

		class options(object):
			reset = 'Reset'
			required_version = 'Version'
			adminuser = 'AdminUser'
			required_agent = 'Agent'
			adminpassword = 'AdminPassword'

	class wdigest_downgrade(object):
		"""Sets wdigest on the machine to explicitly use logon credentials. Counters kb2871997.
		"""

		path = 'powershell/management/wdigest_downgrade'

		class options(object):
			cleanup = 'Cleanup'
			nolock = 'NoLock'
			required_agent = 'Agent'

	class user_to_sid(object):
		"""Converts a specified domain/user to a domain sid.
		"""

		path = 'powershell/management/user_to_sid'

		class options(object):
			required_domain = 'Domain'
			required_user = 'User'
			required_agent = 'Agent'

	class enable_rdp(object):
		"""Enables RDP on the remote machine and adds a firewall exception.
		"""

		path = 'powershell/management/enable_rdp'

		class options(object):
			required_agent = 'Agent'

	class mailraider_get_emailitems(object):
		"""Returns all of the items for the specified folder.
		"""

		path = 'powershell/management/mailraider/get_emailitems'

		class options(object):
			required_maxemails = 'MaxEmails'
			required_agent = 'Agent'
			required_foldername = 'FolderName'

	class logoff(object):
		"""Logs the current user (or all users) off the machine.
		"""

		path = 'powershell/management/logoff'

		class options(object):
			allusers = 'AllUsers'
			required_agent = 'Agent'

	class sid_to_user(object):
		"""Converts a specified domain sid to a user.
		"""

		path = 'powershell/management/sid_to_user'

		class options(object):
			required_agent = 'Agent'
			required_sid = 'SID'

	class vnc(object):
		"""Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.
		"""

		path = 'powershell/management/vnc'

		class options(object):
			required_password = 'Password'
			ipaddress = 'IpAddress'
			required_port = 'Port'
			required_agent = 'Agent'
			required_contype = 'ConType'

	class spawnas(object):
		"""Spawn an agent with the specified logon credentials.
		"""

		path = 'powershell/management/spawnas'

		class options(object):
			username = 'UserName'
			credid = 'CredID'
			domain = 'Domain'
			proxy = 'Proxy'
			required_listener = 'Listener'
			proxycreds = 'ProxyCreds'
			useragent = 'UserAgent'
			password = 'Password'
			required_agent = 'Agent'

	class mailraider_view_email(object):
		"""Selects the specified folder and then outputs the email item at the specified index.
		"""

		path = 'powershell/management/mailraider/view_email'

		class options(object):
			required_index = 'Index'
			required_agent = 'Agent'
			required_foldername = 'FolderName'

	class get_domain_sid(object):
		"""Returns the SID for the current of specified domain.
		"""

		path = 'powershell/management/get_domain_sid'

		class options(object):
			domain = 'Domain'
			required_agent = 'Agent'

	class psinject(object):
		"""Utilizes Powershell to to inject a Stephen Fewer formed ReflectivePick which executes PS codefrom memory in a remote process
		"""

		path = 'powershell/management/psinject'

		class options(object):
			procid = 'ProcId'
			proxycreds = 'ProxyCreds'
			required_agent = 'Agent'
			required_listener = 'Listener'
			procname = 'ProcName'
			proxy = 'Proxy'
			useragent = 'UserAgent'

	class switch_listener(object):
		"""Overwrites the listener controller logic with the agent with the logic from generate_comms() for the specified listener.
		"""

		path = 'powershell/management/switch_listener'

		class options(object):
			required_listener = 'Listener'
			required_agent = 'Agent'

	class mailraider_send_mail(object):
		"""Sends emails using a custom or default template to specified target email addresses.
		"""

		path = 'powershell/management/mailraider/send_mail'

		class options(object):
			body = 'Body'
			attachment = 'Attachment'
			template = 'Template'
			url = 'URL'
			subject = 'Subject'
			targets = 'Targets'
			required_agent = 'Agent'
			targetlist = 'TargetList'

	class invoke_script(object):
		"""Run a custom script. Useful for mass-taskings or script autoruns.
		"""

		path = 'powershell/management/invoke_script'

		class options(object):
			required_scriptcmd = 'ScriptCmd'
			scriptpath = 'ScriptPath'
			required_agent = 'Agent'

	class enable_multi_rdp(object):
		"""[!] WARNING: Experimental! Runs PowerSploit's Invoke-Mimikatz function to patch the Windows terminal service to allow multiple users to establish simultaneous RDP connections.
		"""

		path = 'powershell/management/enable_multi_rdp'

		class options(object):
			required_agent = 'Agent'

	class mailraider_mail_search(object):
		"""Searches the given Outlook folder for items (Emails, Contacts, Tasks, Notes, etc. *Depending on the folder*) and returns any matches found.
		"""

		path = 'powershell/management/mailraider/mail_search'

		class options(object):
			required_maxthreads = 'MaxThreads'
			required_defaultfolder = 'DefaultFolder'
			maxresults = 'MaxResults'
			maxsearch = 'MaxSearch'
			required_agent = 'Agent'
			file = 'File'
			required_keywords = 'Keywords'

	class zipfolder(object):
		"""Zips up a target folder for later exfiltration.
		"""

		path = 'powershell/management/zipfolder'

		class options(object):
			required_folder = 'Folder'
			required_zipfilename = 'ZipFileName'
			required_agent = 'Agent'

	class lock(object):
		"""Locks the workstation's display.
		"""

		path = 'powershell/management/lock'

		class options(object):
			required_agent = 'Agent'

	class runas(object):
		"""Runas knockoff. Will bypass GPO path restrictions.
		"""

		path = 'powershell/management/runas'

		class options(object):
			username = 'UserName'
			credid = 'CredID'
			domain = 'Domain'
			required_cmd = 'Cmd'
			arguments = 'Arguments'
			showwindow = 'ShowWindow'
			password = 'Password'
			required_agent = 'Agent'

	class disable_rdp(object):
		"""Disables RDP on the remote machine.
		"""

		path = 'powershell/management/disable_rdp'

		class options(object):
			required_agent = 'Agent'

	class mailraider_get_subfolders(object):
		"""Returns a list of all the folders in the specified top level folder.
		"""

		path = 'powershell/management/mailraider/get_subfolders'

		class options(object):
			required_defaultfolder = 'DefaultFolder'
			required_agent = 'Agent'

	class restart(object):
		"""Restarts the specified machine.
		"""

		path = 'powershell/management/restart'

		class options(object):
			required_agent = 'Agent'

	class downgrade_account(object):
		"""Set reversible encryption on a given domain account and then force the password to be set on next user login.
		"""

		path = 'powershell/management/downgrade_account'

		class options(object):
			repair = 'Repair'
			domain = 'Domain'
			samaccountname = 'SamAccountName'
			required_agent = 'Agent'
			name = 'Name'

	class mailraider_search_gal(object):
		"""returns any exchange users that match the specified search criteria. Searchable fields are FirstName, LastName, JobTitle, Email-Address, and Department.
		"""

		path = 'powershell/management/mailraider/search_gal'

		class options(object):
			required_maxthreads = 'MaxThreads'
			required_jobtitle = 'JobTitle'
			required_agent = 'Agent'
			dept = 'Dept'
			required_fullname = 'FullName'
			email = 'Email'

	class spawn(object):
		"""Spawns a new agent in a new powershell.exe process.
		"""

		path = 'powershell/management/spawn'

		class options(object):
			proxycreds = 'ProxyCreds'
			syswow64 = 'SysWow64'
			required_agent = 'Agent'
			required_listener = 'Listener'
			proxy = 'Proxy'
			useragent = 'UserAgent'

	class timestomp(object):
		"""Executes time-stomp like functionality by invoking Set-MacAttribute.
		"""

		path = 'powershell/management/timestomp'

		class options(object):
			all = 'All'
			created = 'Created'
			required_filepath = 'FilePath'
			modified = 'Modified'
			required_agent = 'Agent'
			oldfile = 'OldFile'
			accessed = 'Accessed'

	class honeyhash(object):
		"""Inject artificial credentials into LSASS.
		"""

		path = 'powershell/management/honeyhash'

		class options(object):
			required_username = 'UserName'
			required_domain = 'Domain'
			required_password = 'Password'
			required_agent = 'Agent'

class recon(object):
	class find_fruit(object):
		"""Searches a network range for potentially vulnerable web services.
		"""

		path = 'powershell/recon/find_fruit'

		class options(object):
			usessl = 'UseSSL'
			threads = 'Threads'
			required_rhosts = 'Rhosts'
			timeout = 'Timeout'
			showall = 'ShowAll'
			path = 'Path'
			foundonly = 'FoundOnly'
			port = 'Port'
			required_agent = 'Agent'

	class get_sql_server_login_default_pw(object):
		"""Based on the instance name, test if SQL Server is configured with default passwords.
		"""

		path = 'powershell/recon/get_sql_server_login_default_pw'

		class options(object):
			username = 'Username'
			instance = 'Instance'
			password = 'Password'
			required_agent = 'Agent'
			checkall = 'CheckAll'

	class http_login(object):
		"""Tests credentials against Basic Authentication.
		"""

		path = 'powershell/recon/http_login'

		class options(object):
			username = 'Username'
			usessl = 'UseSSL'
			threads = 'Threads'
			required_rhosts = 'Rhosts'
			dictionary = 'Dictionary'
			noping = 'NoPing'
			directory = 'Directory'
			password = 'Password'
			port = 'Port'
			required_agent = 'Agent'

class privesc(object):
	class mcafee_sitelist(object):
		"""Retrieves the plaintext passwords for found McAfee's SiteList.xml files.
		"""

		path = 'powershell/privesc/mcafee_sitelist'

		class options(object):
			required_agent = 'Agent'

	class powerup_service_exe_useradd(object):
		"""Backs up a service's binary and replaces the original with a binary that creates/adds a local administrator.
		"""

		path = 'powershell/privesc/powerup/service_exe_useradd'

		class options(object):
			username = 'UserName'
			required_servicename = 'ServiceName'
			localgroup = 'LocalGroup'
			password = 'Password'
			required_agent = 'Agent'

	class powerup_write_dllhijacker(object):
		"""Writes out a hijackable .dll to the specified path along with a stager.bat that's called by the .dll. wlbsctrl.dll works well for Windows 7. The machine will need to be restarted for the privesc to work.
		"""

		path = 'powershell/privesc/powerup/write_dllhijacker'

		class options(object):
			proxycreds = 'ProxyCreds'
			required_dllpath = 'DllPath'
			required_agent = 'Agent'
			required_listener = 'Listener'
			proxy = 'Proxy'
			useragent = 'UserAgent'

	class powerup_service_stager(object):
		"""Modifies a target service to execute an Empire stager.
		"""

		path = 'powershell/privesc/powerup/service_stager'

		class options(object):
			proxycreds = 'ProxyCreds'
			required_agent = 'Agent'
			required_listener = 'Listener'
			required_servicename = 'ServiceName'
			proxy = 'Proxy'
			useragent = 'UserAgent'

	class powerup_service_useradd(object):
		"""Modifies a target service to create a local user and add it to the local administrators.
		"""

		path = 'powershell/privesc/powerup/service_useradd'

		class options(object):
			username = 'UserName'
			required_servicename = 'ServiceName'
			localgroup = 'LocalGroup'
			password = 'Password'
			required_agent = 'Agent'

	class powerup_service_exe_stager(object):
		"""Backs up a service's binary and replaces the original with a binary that launches a stager.bat.
		"""

		path = 'powershell/privesc/powerup/service_exe_stager'

		class options(object):
			proxycreds = 'ProxyCreds'
			required_agent = 'Agent'
			required_listener = 'Listener'
			required_servicename = 'ServiceName'
			proxy = 'Proxy'
			useragent = 'UserAgent'
			delete = 'Delete'

	class ms16_135(object):
		"""Spawns a new Listener as SYSTEM by leveraging the MS16-135 local exploit. This exploit is for x64 only and only works on unlocked session. Note: the exploit performs fast windows switching, victim's desktop may flash. A named pipe is also created. Thus, opsec is not guaranteed
		"""

		path = 'powershell/privesc/ms16-135'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class powerup_service_exe_restore(object):
		"""Restore a backed up service binary.
		"""

		path = 'powershell/privesc/powerup/service_exe_restore'

		class options(object):
			required_servicename = 'ServiceName'
			backuppath = 'BackupPath'
			required_agent = 'Agent'

	class getsystem(object):
		"""Gets SYSTEM privileges with one of two methods.
		"""

		path = 'powershell/privesc/getsystem'

		class options(object):
			revtoself = 'RevToSelf'
			technique = 'Technique'
			required_agent = 'Agent'
			servicename = 'ServiceName'
			pipename = 'PipeName'
			whoami = 'WhoAmI'

	class ask(object):
		"""Leverages Start-Process' -Verb runAs option inside a YES-Required loop to prompt the user for a high integrity context before running the agent code. UAC will report Powershell is requesting Administrator privileges. Because this does not use the BypassUAC DLLs, it should not trigger any AV alerts.
		"""

		path = 'powershell/privesc/ask'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class powerup_find_dllhijack(object):
		"""Finds generic .DLL hijacking opportunities.
		"""

		path = 'powershell/privesc/powerup/find_dllhijack'

		class options(object):
			excludewindows = 'ExcludeWindows'
			excludeprogramfiles = 'ExcludeProgramFiles'
			excludeowned = 'ExcludeOwned'
			required_agent = 'Agent'

	class tater(object):
		"""Tater is a PowerShell implementation of the Hot Potato Windows Privilege Escalation exploit from @breenmachine and @foxglovesec.
		"""

		path = 'powershell/privesc/tater'

		class options(object):
			taskdelete = 'TaskDelete'
			exhaustudp = 'ExhaustUDP'
			hostname = 'Hostname'
			trigger = 'Trigger'
			required_command = 'Command'
			spooferip = 'SpooferIP'
			required_agent = 'Agent'
			httpport = 'HTTPPort'
			nbnslimit = 'NBNSLimit'
			nbns = 'NBNS'
			ip = 'IP'
			wpaddirecthosts = 'WPADDirectHosts'
			taskname = 'Taskname'
			runtime = 'RunTime'
			wpadport = 'WPADPort'

	class bypassuac_fodhelper(object):
		"""Bypasses UAC by performing an registry modification for FodHelper (based onhttps://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
		"""

		path = 'powershell/privesc/bypassuac_fodhelper'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class bypassuac_env(object):
		"""Bypasses UAC (even with Always Notify level set) by by performing an registry modification of the "windir" value in "Environment" based on James Forshaw findings(https://tyranidslair.blogspot.cz/2017/05/exploiting-environment-variables-in.html)
		"""

		path = 'powershell/privesc/bypassuac_env'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class ms16_032(object):
		"""Spawns a new Listener as SYSTEM by leveraging the MS16-032 local exploit. Note: ~1/6 times the exploit won't work, may need to retry.
		"""

		path = 'powershell/privesc/ms16-032'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class bypassuac(object):
		"""Runs a BypassUAC attack to escape from a medium integrity process to a high integrity process. This attack was originally discovered by Leo Davidson. Empire uses components of MSF's bypassuac injection implementation as well as an adapted version of PowerSploit's Invoke--Shellcode.ps1 script for backend lifting.
		"""

		path = 'powershell/privesc/bypassuac'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class gpp(object):
		"""Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
		"""

		path = 'powershell/privesc/gpp'

		class options(object):
			required_agent = 'Agent'

	class powerup_allchecks(object):
		"""Runs all current checks for Windows privesc vectors.
		"""

		path = 'powershell/privesc/powerup/allchecks'

		class options(object):
			required_agent = 'Agent'

	class bypassuac_wscript(object):
		"""Drops wscript.exe and a custom manifest into C:/Windows/ and then proceeds to execute VBScript using the wscript executablewith the new manifest. The VBScript executed by C:/Windows/wscript.exe will run elevated.
		"""

		path = 'powershell/privesc/bypassuac_wscript'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class bypassuac_sdctlbypass(object):
		"""Bypasses UAC by performing an registry modification for sdclt (based onhttps://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)
		"""

		path = 'powershell/privesc/bypassuac_sdctlbypass'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

	class bypassuac_eventvwr(object):
		"""Bypasses UAC by performing an image hijack on the .msc file extension and starting eventvwr.exe. No files are dropped to disk, making this opsec safe.
		"""

		path = 'powershell/privesc/bypassuac_eventvwr'

		class options(object):
			required_listener = 'Listener'
			useragent = 'UserAgent'
			proxy = 'Proxy'
			required_agent = 'Agent'
			proxycreds = 'ProxyCreds'

class situational_awareness(object):
	class network_powerview_get_forest(object):
		"""Return information about a given forest, including the root domain and SID. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_forest'

		class options(object):
			forest = 'Forest'
			required_agent = 'Agent'

	class network_powerview_find_managed_security_group(object):
		"""This function retrieves all security groups in the domain and identifies ones that have a manager set. It also determines whether the manager has the ability to add or remove members from the group. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_managed_security_group'

		class options(object):
			required_agent = 'Agent'

	class network_powerview_share_finder(object):
		"""Finds shares on machines in the domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/share_finder'

		class options(object):
			delay = 'Delay'
			computername = 'ComputerName'
			checkshareaccess = 'CheckShareAccess'
			domaincontroller = 'DomainController'
			noping = 'NoPing'
			threads = 'Threads'
			domain = 'Domain'
			required_agent = 'Agent'
			computerfilter = 'ComputerFilter'

	class network_powerview_get_domain_policy(object):
		"""Returns the default domain or DC policy for a given domain or domain controller. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_domain_policy'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'
			fulldata = 'FullData'
			resolvesids = 'ResolveSids'
			required_source = 'Source'

	class network_arpscan(object):
		"""Performs an ARP scan against a given range of IPv4 IP Addresses.
		"""

		path = 'powershell/situational_awareness/network/arpscan'

		class options(object):
			range = 'Range'
			cidr = 'CIDR'
			required_agent = 'Agent'

	class host_paranoia(object):
		"""Continuously check running processes for the presence of suspicious users, members of groups, process names, and for any processes running off of USB drives.
		"""

		path = 'powershell/situational_awareness/host/paranoia'

		class options(object):
			watchusers = 'WatchUsers'
			watchprocesses = 'WatchProcesses'
			watchgroups = 'WatchGroups'
			required_agent = 'Agent'

	class network_powerview_get_cached_rdpconnection(object):
		"""Uses remote registry functionality to query all entries for the Windows Remote Desktop Connection Client" on a machine. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_cached_rdpconnection'

		class options(object):
			remoteusername = 'RemoteUserName'
			computername = 'ComputerName'
			required_agent = 'Agent'
			remotepassword = 'RemotePassword'

	class network_smbscanner(object):
		"""Tests a username/password combination across a number of machines.
		"""

		path = 'powershell/situational_awareness/network/smbscanner'

		class options(object):
			required_username = 'UserName'
			credid = 'CredID'
			computername = 'ComputerName'
			required_agent = 'Agent'
			noping = 'NoPing'
			required_password = 'Password'

	class network_powerview_process_hunter(object):
		"""Query the process lists of remote machines, searching for processes with a specific name or owned by a specific user. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/process_hunter'

		class options(object):
			username = 'UserName'
			computername = 'ComputerName'
			targetserver = 'TargetServer'
			delay = 'Delay'
			processname = 'ProcessName'
			computerfilter = 'ComputerFilter'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			userfilter = 'UserFilter'
			groupname = 'GroupName'
			required_agent = 'Agent'
			stoponsuccess = 'StopOnSuccess'
			threads = 'Threads'
			noping = 'NoPing'

	class network_powerview_find_user_field(object):
		"""Searches user object fields for a given word (default *pass*). Default field being searched is 'description'. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_user_field'

		class options(object):
			searchterm = 'SearchTerm'
			domain = 'Domain'
			searchfield = 'SearchField'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'

	class network_portscan(object):
		"""Does a simple port scan using regular sockets, based (pretty) loosely on nmap.
		"""

		path = 'powershell/situational_awareness/network/portscan'

		class options(object):
			skipdiscovery = 'SkipDiscovery'
			readableout = 'ReadableOut'
			hostfile = 'HostFile'
			xmlout = 'XmlOut'
			excludehosts = 'ExcludeHosts'
			topports = 'TopPorts'
			hosts = 'Hosts'
			ports = 'Ports'
			required_agent = 'Agent'
			allformatsout = 'AllformatsOut'
			pingonly = 'PingOnly'
			grepout = 'GrepOut'
			open = 'Open'

	class network_powerview_get_localgroup(object):
		"""Returns a list of all current users in a specified local group on a local or remote machine. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_localgroup'

		class options(object):
			computername = 'ComputerName'
			recurse = 'Recurse'
			listgroups = 'ListGroups'
			required_agent = 'Agent'
			groupname = 'GroupName'
			api = 'API'

	class network_powerview_get_fileserver(object):
		"""Returns a list of all file servers extracted from user homedirectory, scriptpath, and profilepath fields. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_fileserver'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'

	class network_powerview_find_foreign_user(object):
		"""Enumerates users who are in groups outside of their principal domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_foreign_user'

		class options(object):
			username = 'UserName'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'

	class network_powerview_get_dfs_share(object):
		"""Returns a list of all fault-tolerant distributed file systems for a given domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_dfs_share'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'

	class network_powerview_get_computer(object):
		"""Queries the domain for current computer objects. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_computer'

		class options(object):
			computername = 'ComputerName'
			ping = 'Ping'
			fulldata = 'FullData'
			filter = 'Filter'
			printers = 'Printers'
			unconstrained = 'Unconstrained'
			operatingsystem = 'OperatingSystem'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'
			spn = 'SPN'

	class network_get_sql_server_info(object):
		"""Returns basic server and user information from target SQL Servers.
		"""

		path = 'powershell/situational_awareness/network/get_sql_server_info'

		class options(object):
			username = 'Username'
			instance = 'Instance'
			password = 'Password'
			required_agent = 'Agent'
			checkall = 'CheckAll'

	class host_get_pathacl(object):
		"""Enumerates the ACL for a given file path.
		"""

		path = 'powershell/situational_awareness/host/get_pathacl'

		class options(object):
			required_path = 'Path'
			required_agent = 'Agent'

	class network_powerview_get_gpo_computer(object):
		"""Takes a GPO GUID and returns the computers the GPO is applied to. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_gpo_computer'

		class options(object):
			domain = 'Domain'
			required_guid = 'GUID'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'

	class network_powerview_get_domain_controller(object):
		"""Returns the domain controllers for the current domain or the specified domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_domain_controller'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'
			ldap = 'LDAP'

	class host_winenum(object):
		"""Collects revelant information about a host and the current user context.
		"""

		path = 'powershell/situational_awareness/host/winenum'

		class options(object):
			keywords = 'Keywords'
			username = 'UserName'
			required_agent = 'Agent'

	class network_powerview_find_gpo_computer_admin(object):
		"""Takes a computer (or GPO) object and determines what users/groups have administrative access over it. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_gpo_computer_admin'

		class options(object):
			computername = 'ComputerName'
			domaincontroller = 'DomainController'
			localgroup = 'LocalGroup'
			recurse = 'Recurse'
			domain = 'Domain'
			required_agent = 'Agent'
			ouname = 'OUName'

	class network_powerview_find_foreign_group(object):
		"""Enumerates all the members of a given domain's groups and finds users that are not in the queried domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_foreign_group'

		class options(object):
			groupname = 'GroupName'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'

	class network_powerview_user_hunter(object):
		"""Finds which machines users of a specified group are logged into. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/user_hunter'

		class options(object):
			username = 'UserName'
			computername = 'ComputerName'
			domaincontroller = 'DomainController'
			userfilter = 'UserFilter'
			targetserver = 'TargetServer'
			stoponsuccess = 'StopOnSuccess'
			showall = 'ShowAll'
			domain = 'Domain'
			required_agent = 'Agent'
			delay = 'Delay'
			groupname = 'GroupName'
			stealth = 'Stealth'
			threads = 'Threads'
			checkaccess = 'CheckAccess'
			noping = 'NoPing'
			computerfilter = 'ComputerFilter'

	class network_powerview_get_user(object):
		"""Query information for a given user or users in the specified domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_user'

		class options(object):
			username = 'UserName'
			admincount = 'AdminCount'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			spn = 'SPN'
			filter = 'Filter'
			allowdelegation = 'AllowDelegation'
			adspath = 'ADSpath'
			required_agent = 'Agent'

	class host_antivirusproduct(object):
		"""Get antivirus product information.
		"""

		path = 'powershell/situational_awareness/host/antivirusproduct'

		class options(object):
			computername = 'ComputerName'
			required_agent = 'Agent'

	class host_dnsserver(object):
		"""Enumerates the DNS Servers used by a system.
		"""

		path = 'powershell/situational_awareness/host/dnsserver'

		class options(object):
			required_agent = 'Agent'

	class host_computerdetails(object):
		"""Enumerates useful information on the system. By default, all checks are run.
		"""

		path = 'powershell/situational_awareness/host/computerdetails'

		class options(object):
			_4648 = '4648'
			applocker = 'AppLocker'
			required_agent = 'Agent'
			_4624 = '4624'
			savedrdp = 'SavedRDP'
			psscripts = 'PSScripts'

	class network_get_spn(object):
		"""Displays Service Principal Names (SPN) for domain accounts based on SPN service name, domain account, or domain group via LDAP queries.
		"""

		path = 'powershell/situational_awareness/network/get_spn'

		class options(object):
			search = 'Search'
			type = 'Type'
			required_agent = 'Agent'

	class network_powerview_get_domain_trust(object):
		"""Return all domain trusts for the current domain or a specified domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_domain_trust'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'
			ldap = 'LDAP'

	class network_powerview_get_object_acl(object):
		"""Returns the ACLs associated with a specific active directory object. Part of PowerView. WARNING: specify a specific object, otherwise a huge amount of data will be returned.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_object_acl'

		class options(object):
			distinguishedname = 'DistinguishedName'
			name = 'Name'
			adspath = 'ADSpath'
			resolveguids = 'ResolveGUIDs'
			filter = 'Filter'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			samaccountname = 'SamAccountName'
			required_agent = 'Agent'
			rightsfilter = 'RightsFilter'
			adsprefix = 'ADSprefix'

	class host_get_proxy(object):
		"""Enumerates the proxy server and WPAD conents for the current user. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/host/get_proxy'

		class options(object):
			computername = 'ComputerName'
			required_agent = 'Agent'

	class network_powerview_get_group(object):
		"""Gets a list of all current groups in a domain, or all the groups a given user/group object belongs to. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_group'

		class options(object):
			username = 'UserName'
			groupname = 'GroupName'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			filter = 'Filter'
			sid = 'SID'
			admincount = 'AdminCount'
			required_agent = 'Agent'
			fulldata = 'FullData'

	class network_powerview_map_domain_trust(object):
		"""Maps all reachable domain trusts with .CSV output. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/map_domain_trust'

		class options(object):
			domaincontroller = 'DomainController'
			required_agent = 'Agent'
			ldap = 'LDAP'

	class network_powerview_get_group_member(object):
		"""Returns the members of a given group, with the option to "Recurse" to find all effective group members. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_group_member'

		class options(object):
			filter = 'Filter'
			required_groupname = 'GroupName'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			usematchingrule = 'UseMatchingRule'
			sid = 'SID'
			recurse = 'Recurse'
			required_agent = 'Agent'
			fulldata = 'FullData'

	class network_reverse_dns(object):
		"""Performs a DNS Reverse Lookup of a given IPv4 IP Range.
		"""

		path = 'powershell/situational_awareness/network/reverse_dns'

		class options(object):
			range = 'Range'
			cidr = 'CIDR'
			required_agent = 'Agent'

	class network_get_sql_instance_domain(object):
		"""Returns a list of SQL Server instances discovered by querying a domain controller for systems with registered MSSQL service principal names. The function will default to the current user's domain and logon server, but an alternative domain controller can be provided. UDP scanning of management servers is optional.
		"""

		path = 'powershell/situational_awareness/network/get_sql_instance_domain'

		class options(object):
			udptimeout = 'UDPTimeOut'
			username = 'Username'
			computername = 'ComputerName'
			domaincontroller = 'DomainController'
			domainserviceaccount = 'DomainServiceAccount'
			password = 'Password'
			checkmgmt = 'CheckMgmt'
			required_agent = 'Agent'

	class network_powerview_set_ad_object(object):
		"""Takes a SID, name, or SamAccountName to query for a specified domain object, and then sets a specified "PropertyName" to a specified "PropertyValue". Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/set_ad_object'

		class options(object):
			domain = 'Domain'
			name = 'Name'
			sid = 'SID'
			propertyxorvalue = 'PropertyXorValue'
			propertyname = 'PropertyName'
			propertyvalue = 'PropertyValue'
			clearvalue = 'ClearValue'
			required_agent = 'Agent'
			samaccountname = 'SamAccountName'

	class host_monitortcpconnections(object):
		"""Monitors hosts for TCP connections to a specified domain name or IPv4 address. Useful for session hijacking and finding users interacting with sensitive services.
		"""

		path = 'powershell/situational_awareness/host/monitortcpconnections'

		class options(object):
			required_targetdomain = 'TargetDomain'
			required_checkinterval = 'CheckInterval'
			required_agent = 'Agent'

	class network_powerview_get_loggedon(object):
		"""Execute the NetWkstaUserEnum Win32API call to query a given host for actively logged on users. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_loggedon'

		class options(object):
			computername = 'ComputerName'
			required_agent = 'Agent'

	class network_powerview_get_gpo(object):
		"""Gets a list of all current GPOs in a domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_gpo'

		class options(object):
			domain = 'Domain'
			displayname = 'DisplayName'
			gponame = 'GPOname'
			adspath = 'ADSpath'
			computername = 'ComputerName'
			required_agent = 'Agent'
			domaincontroller = 'DomainController'

	class network_powerview_get_rdp_session(object):
		"""Query a given RDP remote service for active sessions and originating IPs (replacement for qwinsta). Note: needs admin rights on the remote server you're querying
		"""

		path = 'powershell/situational_awareness/network/powerview/get_rdp_session'

		class options(object):
			required_computername = 'ComputerName'
			required_agent = 'Agent'

	class network_powerview_get_site(object):
		"""Gets a list of all current sites in a domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_site'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			sitename = 'SiteName'
			adspath = 'ADSpath'
			required_agent = 'Agent'
			fulldata = 'FullData'
			guid = 'GUID'

	class network_powerview_get_ou(object):
		"""Gets a list of all current OUs in a domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_ou'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			adspath = 'ADSpath'
			required_agent = 'Agent'
			fulldata = 'FullData'
			guid = 'GUID'
			ouname = 'OUName'

	class host_get_uaclevel(object):
		"""Enumerates UAC level
		"""

		path = 'powershell/situational_awareness/host/get_uaclevel'

		class options(object):
			required_agent = 'Agent'

	class network_powerview_get_session(object):
		"""Execute the NetSessionEnum Win32API call to query a given host for active sessions on the host. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_session'

		class options(object):
			computername = 'ComputerName'
			required_agent = 'Agent'

	class network_get_exploitable_system(object):
		"""Queries Active Directory for systems likely vulnerable to various Metasploit exploits.
		"""

		path = 'powershell/situational_awareness/network/get_exploitable_system'

		class options(object):
			computername = 'ComputerName'
			ping = 'Ping'
			domain = 'Domain'
			required_agent = 'Agent'
			filter = 'Filter'
			spn = 'SPN'
			operatingsystem = 'OperatingSystem'

	class network_powerview_get_subnet(object):
		"""Gets a list of all current subnets in a domain. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_subnet'

		class options(object):
			domain = 'Domain'
			domaincontroller = 'DomainController'
			sitename = 'SiteName'
			adspath = 'ADSpath'
			required_agent = 'Agent'
			fulldata = 'FullData'

	class network_smbautobrute(object):
		"""Runs an SMB brute against a list of usernames/passwords. Will check the DCs to interrogate the bad password count of the users and will keep bruting until either a valid credential is discoverd or the bad password count reaches one below the threshold. Run "shell net accounts" on a valid agent to determine the lockout threshold. VERY noisy! Generates a ton of traffic on the DCs.
		"""

		path = 'powershell/situational_awareness/network/smbautobrute'

		class options(object):
			stoponsuccess = 'StopOnSuccess'
			required_passwordlist = 'PasswordList'
			required_agent = 'Agent'
			delay = 'Delay'
			userlist = 'UserList'
			required_lockoutthreshold = 'LockoutThreshold'
			showverbose = 'ShowVerbose'

	class host_findtrusteddocuments(object):
		"""This module will enumerate the appropriate registry keys to determine what, if any, trusted documents exist on the host.  It will also enumerate trusted locations.
		"""

		path = 'powershell/situational_awareness/host/findtrusteddocuments'

		class options(object):
			required_agent = 'Agent'

	class network_powerview_find_computer_field(object):
		"""Searches computer object fields for a given word (default *pass*). Default field being searched is 'description'. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_computer_field'

		class options(object):
			searchterm = 'SearchTerm'
			domain = 'Domain'
			searchfield = 'SearchField'
			domaincontroller = 'DomainController'
			required_agent = 'Agent'

	class network_powerview_find_localadmin_access(object):
		"""Finds machines on the local domain where the current user has local administrator access. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_localadmin_access'

		class options(object):
			delay = 'Delay'
			computername = 'ComputerName'
			domaincontroller = 'DomainController'
			noping = 'NoPing'
			threads = 'Threads'
			domain = 'Domain'
			required_agent = 'Agent'
			computerfilter = 'ComputerFilter'

	class network_bloodhound(object):
		"""Execute BloodHound data collection.
		"""

		path = 'powershell/situational_awareness/network/bloodhound'

		class options(object):
			computername = 'ComputerName'
			useradspath = 'UserADSPath'
			domaincontroller = 'DomainController'
			computeradspath = 'ComputerADSpath'
			skipgcdeconfliction = 'SkipGCDeconfliction'
			domain = 'Domain'
			required_agent = 'Agent'
			uri = 'URI'
			globalcatalog = 'GlobalCatalog'
			required_threads = 'Threads'
			required_collectionmethod = 'CollectionMethod'
			required_throttle = 'Throttle'
			userpass = 'UserPass'
			searchforest = 'SearchForest'
			csvfolder = 'CSVFolder'
			csvprefix = 'CSVPrefix'

	class network_powerview_get_forest_domain(object):
		"""Return all domains for a given forest. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/get_forest_domain'

		class options(object):
			forest = 'Forest'
			required_agent = 'Agent'

	class network_powerview_find_gpo_location(object):
		"""Takes a user/group name and optional domain, and determines the computers in the domain the user/group has local admin (or RDP) rights to. Part of PowerView.
		"""

		path = 'powershell/situational_awareness/network/powerview/find_gpo_location'

		class options(object):
			username = 'UserName'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			localgroup = 'LocalGroup'
			required_agent = 'Agent'
			groupname = 'GroupName'

class collection(object):
	class find_interesting_file(object):
		"""Finds sensitive files on the domain.
		"""

		path = 'powershell/collection/find_interesting_file'

		class options(object):
			checkwriteaccess = 'CheckWriteAccess'
			terms = 'Terms'
			freshexes = 'FreshEXES'
			officedocs = 'OfficeDocs'
			required_path = 'Path'
			excludehidden = 'ExcludeHidden'
			creationtime = 'CreationTime'
			required_agent = 'Agent'
			lastaccesstime = 'LastAccessTime'

	class FoxDump(object):
		"""This module will dump any saved passwords from Firefox to the console. This should work for any versionof Firefox above version 32. This will only be successful if the master password is blank or has not been set.
		"""

		path = 'powershell/collection/FoxDump'

		class options(object):
			outfile = 'OutFile'
			required_agent = 'Agent'

	class minidump(object):
		"""Generates a full-memory minidump of a process.
		"""

		path = 'powershell/collection/minidump'

		class options(object):
			processname = 'ProcessName'
			dumpfilepath = 'DumpFilePath'
			required_agent = 'Agent'
			processid = 'ProcessId'

	class get_sql_query(object):
		"""Executes a query on target SQL servers.
		"""

		path = 'powershell/collection/get_sql_query'

		class options(object):
			username = 'Username'
			instance = 'Instance'
			password = 'Password'
			required_agent = 'Agent'
			required_query = 'Query'

	class keylogger(object):
		"""Logs keys pressed, time and the active window (when changed).
		"""

		path = 'powershell/collection/keylogger'

		class options(object):
			required_agent = 'Agent'

	class file_finder(object):
		"""Finds sensitive files on the domain.
		"""

		path = 'powershell/collection/file_finder'

		class options(object):
			computername = 'ComputerName'
			terms = 'Terms'
			officedocs = 'OfficeDocs'
			searchsysvol = 'SearchSYSVOL'
			checkwriteaccess = 'CheckWriteAccess'
			creationtime = 'CreationTime'
			domain = 'Domain'
			required_agent = 'Agent'
			lastaccesstime = 'LastAccessTime'
			delay = 'Delay'
			threads = 'Threads'
			freshexes = 'FreshEXES'
			noping = 'NoPing'
			sharelist = 'ShareList'
			excludehidden = 'ExcludeHidden'
			computerfilter = 'ComputerFilter'

	class WebcamRecorder(object):
		"""This module uses the DirectX.Capture and DShowNET .NET assemblies to capture video from a webcam.
		"""

		path = 'powershell/collection/WebcamRecorder'

		class options(object):
			outpath = 'OutPath'
			recordtime = 'RecordTime'
			required_agent = 'Agent'

	class ChromeDump(object):
		"""This module will decrypt passwords saved in chrome and display them in the console.
		"""

		path = 'powershell/collection/ChromeDump'

		class options(object):
			outfile = 'OutFile'
			required_agent = 'Agent'

	class USBKeylogger(object):
		"""Logs USB keys pressed using Event Tracing for Windows (ETW)
		"""

		path = 'powershell/collection/USBKeylogger'

		class options(object):
			required_agent = 'Agent'

	class screenshot(object):
		"""Takes a screenshot of the current desktop and returns the output as a .PNG.
		"""

		path = 'powershell/collection/screenshot'

		class options(object):
			ratio = 'Ratio'
			required_agent = 'Agent'

	class vaults_remove_keepass_config_trigger(object):
		"""This module removes all triggers from all KeePass configs found by Find-KeePassConfig.
		"""

		path = 'powershell/collection/vaults/remove_keepass_config_trigger'

		class options(object):
			required_agent = 'Agent'

	class netripper(object):
		"""Injects NetRipper into targeted processes, which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.
		"""

		path = 'powershell/collection/netripper'

		class options(object):
			loglocation = 'LogLocation'
			processid = 'ProcessID'
			required_agent = 'Agent'
			datalimit = 'Datalimit'
			processname = 'ProcessName'
			required_searchstrings = 'SearchStrings'
			alldata = 'AllData'

	class get_sql_column_sample_data(object):
		"""Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.
		"""

		path = 'powershell/collection/get_sql_column_sample_data'

		class options(object):
			username = 'Username'
			checkall = 'CheckAll'
			nodefaults = 'NoDefaults'
			required_agent = 'Agent'
			instance = 'Instance'
			password = 'Password'

	class browser_data(object):
		"""Search through browser history or bookmarks
		"""

		path = 'powershell/collection/browser_data'

		class options(object):
			datatype = 'DataType'
			username = 'UserName'
			search = 'Search'
			required_agent = 'Agent'
			browser = 'Browser'

	class inveigh(object):
		"""Inveigh is a Windows PowerShell LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool. Note that this module exposes only a subset of Inveigh's parameters. Inveigh can be used through Empire's scriptimport and scriptcmd if additional parameters are needed.
		"""

		path = 'powershell/collection/inveigh'

		class options(object):
			proxyport = 'ProxyPort'
			http = 'HTTP'
			wpadauth = 'WPADAuth'
			spooferipsreply = 'SpooferIPsReply'
			spooferhostsreply = 'SpooferHostsReply'
			spooferipsignore = 'SpooferIPsIgnore'
			spooferrepeat = 'SpooferRepeat'
			mdnstypes = 'mDNSTypes'
			spooferlearningdelay = 'SpooferLearningDelay'
			smb = 'SMB'
			httpauth = 'HTTPAuth'
			consoleunique = 'ConsoleUnique'
			llmnr = 'LLMNR'
			inspect = 'Inspect'
			spooferip = 'SpooferIP'
			proxy = 'Proxy'
			spooferhostsignore = 'SpooferHostsIgnore'
			httpresponse = 'HTTPResponse'
			mdns = 'mDNS'
			consolestatus = 'ConsoleStatus'
			elevatedprivilege = 'ElevatedPrivilege'
			ip = 'IP'
			nbnstypes = 'NBNSTypes'
			httpcontenttype = 'HTTPContentType'
			spooferlearning = 'SpooferLearning'
			required_agent = 'Agent'
			runcount = 'RunCount'
			nbns = 'NBNS'
			required_runtime = 'RunTime'
			consoleoutput = 'ConsoleOutput'

	class vaults_find_keepass_config(object):
		"""This module finds and parses any KeePass.config.xml (2.X) and KeePass.ini (1.X) files.
		"""

		path = 'powershell/collection/vaults/find_keepass_config'

		class options(object):
			required_agent = 'Agent'

	class clipboard_monitor(object):
		"""Monitors the clipboard on a specified interval for changes to copied text.
		"""

		path = 'powershell/collection/clipboard_monitor'

		class options(object):
			collectionlimit = 'CollectionLimit'
			required_pollinterval = 'PollInterval'
			required_agent = 'Agent'

	class packet_capture(object):
		"""Starts a packet capture on a host using netsh.
		"""

		path = 'powershell/collection/packet_capture'

		class options(object):
			required_maxsize = 'MaxSize'
			required_tracefile = 'TraceFile'
			persistent = 'Persistent'
			required_agent = 'Agent'
			stoptrace = 'StopTrace'

	class prompt(object):
		"""Prompts the current user to enter their credentials in a forms box and returns the results.
		"""

		path = 'powershell/collection/prompt'

		class options(object):
			required_msgtext = 'MsgText'
			required_icontype = 'IconType'
			required_agent = 'Agent'
			required_title = 'Title'

	class vaults_get_keepass_config_trigger(object):
		"""This module extracts out the trigger specifications from a KeePass 2.X configuration XML file.
		"""

		path = 'powershell/collection/vaults/get_keepass_config_trigger'

		class options(object):
			required_agent = 'Agent'

	class ninjacopy(object):
		"""Copies a file from an NTFS partitioned volume by reading the raw volume and parsing the NTFS structures.
		"""

		path = 'powershell/collection/ninjacopy'

		class options(object):
			required_path = 'Path'
			computername = 'ComputerName'
			localdestination = 'LocalDestination'
			required_agent = 'Agent'
			remotedestination = 'RemoteDestination'

	class vaults_add_keepass_config_trigger(object):
		"""This module adds a KeePass exfiltration trigger to all KeePass configs found by Find-KeePassConfig.
		"""

		path = 'powershell/collection/vaults/add_keepass_config_trigger'

		class options(object):
			required_action = 'Action'
			required_triggername = 'TriggerName'
			exportpath = 'ExportPath'
			required_agent = 'Agent'

	class get_indexed_item(object):
		"""Gets files which have been indexed by Windows desktop search.
		"""

		path = 'powershell/collection/get_indexed_item'

		class options(object):
			required_terms = 'Terms'
			required_agent = 'Agent'

	class vaults_keethief(object):
		"""This module retrieves database mastey key information for unlocked KeePass database.
		"""

		path = 'powershell/collection/vaults/keethief'

		class options(object):
			required_agent = 'Agent'

class exploitation(object):
	class exploit_jboss(object):
		"""Exploit vulnerable JBoss Services.
		"""

		path = 'powershell/exploitation/exploit_jboss'

		class options(object):
			required_jmxconsole = 'JMXConsole'
			usessl = 'UseSSL'
			required_appname = 'AppName'
			required_agent = 'Agent'
			required_warfile = 'WarFile'
			required_rhost = 'Rhost'
			required_port = 'Port'

	class exploit_jenkins(object):
		"""Run command on unauthenticated Jenkins Script consoles.
		"""

		path = 'powershell/exploitation/exploit_jenkins'

		class options(object):
			required_cmd = 'Cmd'
			required_rhost = 'Rhost'
			required_agent = 'Agent'
			required_port = 'Port'

	class exploit_eternalblue(object):
		"""Port of MS17_010 Metasploit module to powershell. Exploits targeted system and executes specified shellcode. Windows 7 and 2008 R2 supported. Potential for a BSOD 
		"""

		path = 'powershell/exploitation/exploit_eternalblue'

		class options(object):
			required_initialgrooms = 'InitialGrooms'
			required_maxattempts = 'MaxAttempts'
			required_shellcode = 'Shellcode'
			required_target = 'Target'
			required_agent = 'Agent'

class exfiltration(object):
	class exfil_dropbox(object):
		"""Upload a file to dropbox 
		"""

		path = 'powershell/exfiltration/exfil_dropbox'

		class options(object):
			required_sourcefilepath = 'SourceFilePath'
			required_apikey = 'ApiKey'
			required_targetfilepath = 'TargetFilePath'
			required_agent = 'Agent'

	class egresscheck(object):
		"""This module will generate traffic on a provided range of ports and supports both TCP and UDP. Useful to identify direct egress channels.
		"""

		path = 'powershell/exfiltration/egresscheck'

		class options(object):
			required_delay = 'delay'
			required_ip = 'ip'
			required_protocol = 'protocol'
			required_agent = 'Agent'
			required_portrange = 'portrange'

class code_execution(object):
	class invoke_shellcodemsil(object):
		"""Execute shellcode within the context of the running PowerShell process without making any Win32 function calls. Warning: This script has no way to validate that your shellcode is 32 vs. 64-bit!Note: Your shellcode must end in a ret (0xC3) and maintain proper stack alignment or PowerShell will crash!
		"""

		path = 'powershell/code_execution/invoke_shellcodemsil'

		class options(object):
			required_shellcode = 'Shellcode'
			required_agent = 'Agent'

	class invoke_dllinjection(object):
		"""Uses PowerSploit's Invoke-DLLInjection to inject  a Dll into the process ID of your choosing.
		"""

		path = 'powershell/code_execution/invoke_dllinjection'

		class options(object):
			required_processid = 'ProcessID'
			required_agent = 'Agent'
			required_dll = 'Dll'

	class invoke_shellcode(object):
		"""Uses PowerSploit's Invoke--Shellcode to inject shellcode into the process ID of your choosing or within the context of the running PowerShell process. If you're injecting custom shellcode, make sure it's in the correct format and matches the architecture of the process you're injecting into.
		"""

		path = 'powershell/code_execution/invoke_shellcode'

		class options(object):
			processid = 'ProcessID'
			lhost = 'Lhost'
			required_agent = 'Agent'
			listener = 'Listener'
			lport = 'Lport'
			shellcode = 'Shellcode'
			payload = 'Payload'

	class invoke_metasploitpayload(object):
		"""Spawns a new, hidden PowerShell window that downloadsand executes a Metasploit payload. This relies on theexploit/multi/scripts/web_delivery metasploit module.
		"""

		path = 'powershell/code_execution/invoke_metasploitpayload'

		class options(object):
			required_url = 'URL'
			required_agent = 'Agent'

	class invoke_reflectivepeinjection(object):
		"""Uses PowerSploit's Invoke-ReflectivePEInjection to reflectively load a DLL/EXE in to the PowerShell process or reflectively load a DLL in to a remote process.
		"""

		path = 'powershell/code_execution/invoke_reflectivepeinjection'

		class options(object):
			procid = 'ProcId'
			required_forceaslr = 'ForceASLR'
			dllpath = 'DllPath'
			exeargs = 'ExeArgs'
			peurl = 'PEUrl'
			required_agent = 'Agent'
			computername = 'ComputerName'

class trollsploit(object):
	class rick_ascii(object):
		"""Spawns a a new powershell.exe process that runs Lee Holmes' ASCII Rick Roll.
		"""

		path = 'powershell/trollsploit/rick_ascii'

		class options(object):
			required_agent = 'Agent'

	class wlmdr(object):
		"""Displays a balloon reminder in the taskbar.
		"""

		path = 'powershell/trollsploit/wlmdr'

		class options(object):
			required_message = 'Message'
			required_icontype = 'IconType'
			required_agent = 'Agent'
			required_title = 'Title'

	class wallpaper(object):
		"""Uploads a .jpg image to the target and sets it as the desktop wallpaper.
		"""

		path = 'powershell/trollsploit/wallpaper'

		class options(object):
			required_localimagepath = 'LocalImagePath'
			required_agent = 'Agent'

	class thunderstruck(object):
		"""Play's a hidden version of AC/DC's Thunderstruck video while maxing out a computer's volume.
		"""

		path = 'powershell/trollsploit/thunderstruck'

		class options(object):
			videourl = 'VideoURL'
			required_agent = 'Agent'

	class rick_astley(object):
		"""Runs @SadProcessor's beeping rickroll.
		"""

		path = 'powershell/trollsploit/rick_astley'

		class options(object):
			required_agent = 'Agent'

	class message(object):
		"""Displays a specified message to the user.
		"""

		path = 'powershell/trollsploit/message'

		class options(object):
			required_msgtext = 'MsgText'
			required_icontype = 'IconType'
			required_agent = 'Agent'
			required_title = 'Title'

	class voicetroll(object):
		"""Reads text aloud via synthesized voice on target.
		"""

		path = 'powershell/trollsploit/voicetroll'

		class options(object):
			required_voicetext = 'VoiceText'
			required_agent = 'Agent'

	class process_killer(object):
		"""Kills any process starting with a particular name.
		"""

		path = 'powershell/trollsploit/process_killer'

		class options(object):
			required_processname = 'ProcessName'
			required_sleep = 'Sleep'
			silent = 'Silent'
			required_agent = 'Agent'

	class get_schwifty(object):
		"""Play's a hidden version of Rick and Morty Get Schwifty video while maxing out a computer's volume.
		"""

		path = 'powershell/trollsploit/get_schwifty'

		class options(object):
			videourl = 'VideoURL'
			required_agent = 'Agent'

class credentials(object):
	class enum_cred_store(object):
		"""Dumps plaintext credentials from the Windows Credential Manager for the current interactive user.
		"""

		path = 'powershell/credentials/enum_cred_store'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_mimitokens(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to list or enumerate tokens.
		"""

		path = 'powershell/credentials/mimikatz/mimitokens'

		class options(object):
			elevate = 'elevate'
			user = 'user'
			admin = 'admin'
			revert = 'revert'
			domainadmin = 'domainadmin'
			list = 'list'
			id = 'id'
			required_agent = 'Agent'

	class tokens(object):
		"""Runs PowerSploit's Invoke-TokenManipulation to enumerate Logon Tokens available and uses them to create new processes. Similar to Incognito's functionality. Note: if you select ImpersonateUser or CreateProcess, you must specify one of Username, ProcessID, Process, or ThreadId.
		"""

		path = 'powershell/credentials/tokens'

		class options(object):
			processid = 'ProcessID'
			noui = 'NoUI'
			showall = 'ShowAll'
			required_agent = 'Agent'
			processargs = 'ProcessArgs'
			whoami = 'WhoAmI'
			username = 'Username'
			revtoself = 'RevToSelf'
			process = 'Process'
			createprocess = 'CreateProcess'
			impersonateuser = 'ImpersonateUser'
			threadid = 'ThreadId'

	class mimikatz_cache(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract MSCache(v2) hashes.
		"""

		path = 'powershell/credentials/mimikatz/cache'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_silver_ticket(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to generate a silver ticket for a server/service and inject it into memory.
		"""

		path = 'powershell/credentials/mimikatz/silver_ticket'

		class options(object):
			groups = 'groups'
			credid = 'CredID'
			domain = 'domain'
			required_user = 'user'
			required_service = 'service'
			sid = 'sid'
			rc4 = 'rc4'
			id = 'id'
			required_agent = 'Agent'
			target = 'target'

	class mimikatz_golden_ticket(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to generate a golden ticket and inject it into memory.
		"""

		path = 'powershell/credentials/mimikatz/golden_ticket'

		class options(object):
			credid = 'CredID'
			domain = 'domain'
			required_user = 'user'
			groups = 'groups'
			sid = 'sid'
			krbtgt = 'krbtgt'
			sids = 'sids'
			id = 'id'
			required_agent = 'Agent'
			endin = 'endin'

	class mimikatz_certs(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract all certificates to the local directory.
		"""

		path = 'powershell/credentials/mimikatz/certs'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_dcsync(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract a given account password through Mimikatz's lsadump::dcsync module. This doesn't need code execution on a given DC, but needs to be run from a user context with DA equivalent privileges.
		"""

		path = 'powershell/credentials/mimikatz/dcsync'

		class options(object):
			domain = 'domain'
			required_user = 'user'
			required_agent = 'Agent'
			dc = 'dc'

	class mimikatz_dcsync_hashdump(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to collect all domain hashes using Mimikatz'slsadump::dcsync module. This doesn't need code execution on a given DC, but needs to be run froma user context with DA equivalent privileges.
		"""

		path = 'powershell/credentials/mimikatz/dcsync_hashdump'

		class options(object):
			active = 'Active'
			domain = 'Domain'
			computers = 'Computers'
			forest = 'Forest'
			required_agent = 'Agent'

	class sessiongopher(object):
		"""Extract saved sessions & passwords for WinSCP, PuTTY, SuperPuTTY, FileZilla, RDP, .ppk files, .rdp files, .sdtid files
		"""

		path = 'powershell/credentials/sessiongopher'

		class options(object):
			p = 'p'
			u = 'u'
			thorough = 'Thorough'
			o = 'o'
			alldomain = 'AllDomain'
			il = 'iL'
			required_agent = 'Agent'
			target = 'Target'

	class mimikatz_purge(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to purge all current kerberos tickets from memory.
		"""

		path = 'powershell/credentials/mimikatz/purge'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_pth(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to execute sekurlsa::pth to create a new process. with a specific user's hash. Use credentials/tokens to steal the token afterwards.
		"""

		path = 'powershell/credentials/mimikatz/pth'

		class options(object):
			credid = 'CredID'
			domain = 'domain'
			ntlm = 'ntlm'
			user = 'user'
			required_agent = 'Agent'

	class credential_injection(object):
		"""Runs PowerSploit's Invoke-CredentialInjection to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).
		"""

		path = 'powershell/credentials/credential_injection'

		class options(object):
			existingwinlogon = 'ExistingWinLogon'
			credid = 'CredID'
			authpackage = 'AuthPackage'
			username = 'UserName'
			domainname = 'DomainName'
			logontype = 'LogonType'
			newwinlogon = 'NewWinLogon'
			password = 'Password'
			required_agent = 'Agent'

	class invoke_kerberoast(object):
		"""Requests kerberos tickets for all users with a non-null service principal name (SPN) and extracts them into a format ready for John or Hashcat.
		"""

		path = 'powershell/credentials/invoke_kerberoast'

		class options(object):
			admincount = 'AdminCount'
			domain = 'Domain'
			ldapfilter = 'LDAPFilter'
			identity = 'Identity'
			searchbase = 'SearchBase'
			searchscope = 'SearchScope'
			outputformat = 'OutputFormat'
			required_agent = 'Agent'
			server = 'Server'

	class mimikatz_logonpasswords(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract plaintext credentials from memory.
		"""

		path = 'powershell/credentials/mimikatz/logonpasswords'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_extract_tickets(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract kerberos tickets from memory in base64-encoded form.
		"""

		path = 'powershell/credentials/mimikatz/extract_tickets'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_sam(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract hashes from the Security Account Managers (SAM) database.
		"""

		path = 'powershell/credentials/mimikatz/sam'

		class options(object):
			required_agent = 'Agent'

	class powerdump(object):
		"""Dumps hashes from the local system using Posh-SecMod's Invoke-PowerDump
		"""

		path = 'powershell/credentials/powerdump'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_command(object):
		"""Runs PowerSploit's Invoke-Mimikatz function with a custom command.
		"""

		path = 'powershell/credentials/mimikatz/command'

		class options(object):
			required_command = 'Command'
			required_agent = 'Agent'

	class mimikatz_trust_keys(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract domain trust keys from a domain controller.
		"""

		path = 'powershell/credentials/mimikatz/trust_keys'

		class options(object):
			required_method = 'Method'
			required_agent = 'Agent'

	class vault_credential(object):
		"""Runs PowerSploit's Get-VaultCredential to display Windows vault credential objects including cleartext web credentials.
		"""

		path = 'powershell/credentials/vault_credential'

		class options(object):
			required_agent = 'Agent'

	class mimikatz_lsadump(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to extract a particular user hash from memory. Useful on domain controllers.
		"""

		path = 'powershell/credentials/mimikatz/lsadump'

		class options(object):
			username = 'Username'
			required_agent = 'Agent'

class persistence(object):
	class misc_add_sid_history(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to execute misc::addsid to add sid history for a user. ONLY APPLICABLE ON DOMAIN CONTROLLERS!
		"""

		path = 'powershell/persistence/misc/add_sid_history'

		class options(object):
			required_groups = 'Groups'
			required_user = 'User'
			required_agent = 'Agent'

	class misc_install_ssp(object):
		"""Installs a security support provider (SSP) dll.
		"""

		path = 'powershell/persistence/misc/install_ssp'

		class options(object):
			required_path = 'Path'
			required_agent = 'Agent'

	class userland_schtasks(object):
		"""Persist a stager (or script) using schtasks. This has a moderate detection/removal rating.
		"""

		path = 'powershell/persistence/userland/schtasks'

		class options(object):
			dailytime = 'DailyTime'
			proxycreds = 'ProxyCreds'
			extfile = 'ExtFile'
			cleanup = 'Cleanup'
			required_taskname = 'TaskName'
			idletime = 'IdleTime'
			adspath = 'ADSPath'
			required_agent = 'Agent'
			listener = 'Listener'
			regpath = 'RegPath'
			proxy = 'Proxy'
			useragent = 'UserAgent'

	class misc_add_netuser(object):
		"""Adds a domain user or a local user to the current (or remote) machine, if permissions allow,
		"""

		path = 'powershell/persistence/misc/add_netuser'

		class options(object):
			username = 'UserName'
			computername = 'ComputerName'
			domain = 'Domain'
			required_agent = 'Agent'
			groupname = 'GroupName'
			password = 'Password'

	class elevated_wmi_updater(object):
		"""Persist a stager (or script) using a permanent WMI subscription. This has a difficult detection/removal rating.
		"""

		path = 'powershell/persistence/elevated/wmi_updater'

		class options(object):
			extfile = 'ExtFile'
			dailytime = 'DailyTime'
			cleanup = 'Cleanup'
			required_subname = 'SubName'
			atstartup = 'AtStartup'
			required_launcher = 'Launcher'
			required_webfile = 'WebFile'
			required_agent = 'Agent'

	class elevated_schtasks(object):
		"""Persist a stager (or script) using schtasks running as SYSTEM. This has a moderate detection/removal rating.
		"""

		path = 'powershell/persistence/elevated/schtasks'

		class options(object):
			dailytime = 'DailyTime'
			onlogon = 'OnLogon'
			extfile = 'ExtFile'
			proxycreds = 'ProxyCreds'
			cleanup = 'Cleanup'
			required_taskname = 'TaskName'
			idletime = 'IdleTime'
			adspath = 'ADSPath'
			required_agent = 'Agent'
			listener = 'Listener'
			regpath = 'RegPath'
			proxy = 'Proxy'
			useragent = 'UserAgent'

	class elevated_wmi(object):
		"""Persist a stager (or script) using a permanent WMI subscription. This has a difficult detection/removal rating.
		"""

		path = 'powershell/persistence/elevated/wmi'

		class options(object):
			listener = 'Listener'
			dailytime = 'DailyTime'
			cleanup = 'Cleanup'
			required_subname = 'SubName'
			proxy = 'Proxy'
			atstartup = 'AtStartup'
			extfile = 'ExtFile'
			useragent = 'UserAgent'
			proxycreds = 'ProxyCreds'
			required_agent = 'Agent'

	class userland_registry(object):
		"""Persist a stager (or script) via the HKCU:SOFTWARE/Microsoft/Windows/CurrentVersion/Run registry key. This has an easy detection/removal rating.
		"""

		path = 'powershell/persistence/userland/registry'

		class options(object):
			proxycreds = 'ProxyCreds'
			eventlogid = 'EventLogID'
			extfile = 'ExtFile'
			cleanup = 'Cleanup'
			adspath = 'ADSPath'
			required_agent = 'Agent'
			listener = 'Listener'
			required_keyname = 'KeyName'
			regpath = 'RegPath'
			proxy = 'Proxy'
			useragent = 'UserAgent'

	class misc_skeleton_key(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to execute misc::skeleton to implant a skeleton key w/ password 'mimikatz'. ONLY APPLICABLE ON DOMAIN CONTROLLERS!
		"""

		path = 'powershell/persistence/misc/skeleton_key'

		class options(object):
			required_agent = 'Agent'

	class misc_get_ssps(object):
		"""Enumerates all loaded security packages (SSPs).
		"""

		path = 'powershell/persistence/misc/get_ssps'

		class options(object):
			required_agent = 'Agent'

	class powerbreach_eventlog(object):
		"""Starts the event-loop backdoor.
		"""

		path = 'powershell/persistence/powerbreach/eventlog'

		class options(object):
			required_agent = 'Agent'
			required_listener = 'Listener'
			outfile = 'OutFile'
			required_trigger = 'Trigger'
			required_sleep = 'Sleep'
			required_timeout = 'Timeout'

	class elevated_registry(object):
		"""Persist a stager (or script) via the HKLM:SOFTWARE/Microsoft/Windows/CurrentVersion/Run registry key. This has an easy detection/removal rating.
		"""

		path = 'powershell/persistence/elevated/registry'

		class options(object):
			listener = 'Listener'
			proxycreds = 'ProxyCreds'
			required_keyname = 'KeyName'
			regpath = 'RegPath'
			proxy = 'Proxy'
			extfile = 'ExtFile'
			useragent = 'UserAgent'
			cleanup = 'Cleanup'
			adspath = 'ADSPath'
			required_agent = 'Agent'

	class misc_disable_machine_acct_change(object):
		"""Disables the machine account for the target system from changing its password automatically.
		"""

		path = 'powershell/persistence/misc/disable_machine_acct_change'

		class options(object):
			cleanup = 'CleanUp'
			required_agent = 'Agent'

	class misc_debugger(object):
		"""Sets the debugger for a specified target binary to be cmd.exe, another binary of your choice, or a listern stager. This can be launched from the ease-of-access center (ctrl+U).
		"""

		path = 'powershell/persistence/misc/debugger'

		class options(object):
			required_targetbinary = 'TargetBinary'
			triggerbinary = 'TriggerBinary'
			listener = 'Listener'
			cleanup = 'Cleanup'
			regpath = 'RegPath'
			required_agent = 'Agent'

	class powerbreach_resolver(object):
		"""Starts the Resolver Backdoor.
		"""

		path = 'powershell/persistence/powerbreach/resolver'

		class options(object):
			required_hostname = 'Hostname'
			required_agent = 'Agent'
			required_listener = 'Listener'
			outfile = 'OutFile'
			required_trigger = 'Trigger'
			required_sleep = 'Sleep'
			required_timeout = 'Timeout'

	class misc_memssp(object):
		"""Runs PowerSploit's Invoke-Mimikatz function to execute misc::memssp to log all authentication events to C:/Windows/System32/mimisla.log.
		"""

		path = 'powershell/persistence/misc/memssp'

		class options(object):
			required_agent = 'Agent'

	class powerbreach_deaduser(object):
		"""Backup backdoor for a backdoor user.
		"""

		path = 'powershell/persistence/powerbreach/deaduser'

		class options(object):
			required_username = 'Username'
			domain = 'Domain'
			required_agent = 'Agent'
			required_listener = 'Listener'
			outfile = 'OutFile'
			required_sleep = 'Sleep'
			required_timeout = 'Timeout'

	class userland_backdoor_lnk(object):
		"""Backdoor a specified .LNK file with a version that launches the original binary and then an Empire stager.
		"""

		path = 'powershell/persistence/userland/backdoor_lnk'

		class options(object):
			required_listener = 'Listener'
			proxycreds = 'ProxyCreds'
			cleanup = 'Cleanup'
			required_regpath = 'RegPath'
			proxy = 'Proxy'
			extfile = 'ExtFile'
			useragent = 'UserAgent'
			required_agent = 'Agent'
			required_lnkpath = 'LNKPath'

class lateral_movement(object):
	class invoke_wmi_debugger(object):
		"""Uses WMI to set the debugger for a target binary on a remote machine to be cmd.exe or a stager.
		"""

		path = 'powershell/lateral_movement/invoke_wmi_debugger'

		class options(object):
			listener = 'Listener'
			credid = 'CredID'
			required_computername = 'ComputerName'
			cleanup = 'Cleanup'
			required_targetbinary = 'TargetBinary'
			username = 'UserName'
			binary = 'Binary'
			regpath = 'RegPath'
			password = 'Password'
			required_agent = 'Agent'

	class invoke_sqloscmd(object):
		"""Executes a command or stager on remote hosts using xp_cmdshell.
		"""

		path = 'powershell/lateral_movement/invoke_sqloscmd'

		class options(object):
			listener = 'Listener'
			credid = 'CredID'
			command = 'Command'
			proxy = 'Proxy'
			username = 'UserName'
			required_instance = 'Instance'
			useragent = 'UserAgent'
			proxycreds = 'ProxyCreds'
			password = 'Password'
			required_agent = 'Agent'

	class new_gpo_immediate_task(object):
		"""Builds an 'Immediate' schtask to push out through a specified GPO.
		"""

		path = 'powershell/lateral_movement/new_gpo_immediate_task'

		class options(object):
			gpodisplayname = 'GPODisplayName'
			proxycreds = 'ProxyCreds'
			remove = 'Remove'
			required_taskname = 'TaskName'
			domain = 'Domain'
			domaincontroller = 'DomainController'
			gponame = 'GPOname'
			taskdescription = 'TaskDescription'
			required_agent = 'Agent'
			required_listener = 'Listener'
			proxy = 'Proxy'
			required_taskauthor = 'TaskAuthor'
			useragent = 'UserAgent'

	class invoke_psremoting(object):
		"""Executes a stager on remote hosts using PSRemoting.
		"""

		path = 'powershell/lateral_movement/invoke_psremoting'

		class options(object):
			required_listener = 'Listener'
			credid = 'CredID'
			required_computername = 'ComputerName'
			proxy = 'Proxy'
			username = 'UserName'
			proxycreds = 'ProxyCreds'
			useragent = 'UserAgent'
			password = 'Password'
			required_agent = 'Agent'

	class invoke_sshcommand(object):
		"""Executes a command on a remote host via SSH.
		"""

		path = 'powershell/lateral_movement/invoke_sshcommand'

		class options(object):
			username = 'Username'
			credid = 'CredID'
			required_ip = 'IP'
			required_agent = 'Agent'
			required_command = 'Command'
			password = 'Password'

	class invoke_wmi(object):
		"""Executes a stager on remote hosts using WMI.
		"""

		path = 'powershell/lateral_movement/invoke_wmi'

		class options(object):
			required_listener = 'Listener'
			credid = 'CredID'
			required_computername = 'ComputerName'
			proxy = 'Proxy'
			username = 'UserName'
			proxycreds = 'ProxyCreds'
			useragent = 'UserAgent'
			password = 'Password'
			required_agent = 'Agent'

	class inveigh_relay(object):
		"""Inveigh's SMB relay function. This module can be used to relay incoming HTTP/Proxy NTLMv1/NTLMv2 authentication requests to an SMB target. If the authentication is successfully relayed and the account has the correct privilege, a specified command or Empire launcher will be executed on the target PSExec style. This module works best while also running collection/inveigh with HTTP disabled. Note that this module exposes only a subset of Inveigh Relay's parameters. Inveigh Relay can be used through Empire's scriptimport and scriptcmd if additional parameters are needed.
		"""

		path = 'powershell/lateral_movement/inveigh_relay'

		class options(object):
			proxyport = 'ProxyPort'
			proxycreds = 'ProxyCreds'
			http = 'HTTP'
			consoleunique = 'ConsoleUnique'
			consolestatus = 'ConsoleStatus'
			required_target = 'Target'
			service = 'Service'
			wpadauth = 'WPADAuth'
			proxy_ = 'Proxy_'
			usernames = 'Usernames'
			required_agent = 'Agent'
			smb1 = 'SMB1'
			listener = 'Listener'
			command = 'Command'
			proxy = 'Proxy'
			useragent = 'UserAgent'
			required_runtime = 'RunTime'
			consoleoutput = 'ConsoleOutput'

	class jenkins_script_console(object):
		"""Exploit unauthenticated Jenkins Script consoles.
		"""

		path = 'powershell/lateral_movement/jenkins_script_console'

		class options(object):
			proxycreds = 'ProxyCreds'
			required_agent = 'Agent'
			required_listener = 'Listener'
			proxy = 'Proxy'
			useragent = 'UserAgent'
			required_port = 'Port'
			required_rhost = 'Rhost'

	class invoke_dcom(object):
		"""Executes a stager on remote hosts using DCOM.
		"""

		path = 'powershell/lateral_movement/invoke_dcom'

		class options(object):
			required_listener = 'Listener'
			credid = 'CredID'
			required_computername = 'ComputerName'
			proxy = 'Proxy'
			proxycreds = 'ProxyCreds'
			useragent = 'UserAgent'
			required_method = 'Method'
			required_agent = 'Agent'

	class invoke_psexec(object):
		"""Executes a stager on remote hosts using PsExec type functionality.
		"""

		path = 'powershell/lateral_movement/invoke_psexec'

		class options(object):
			listener = 'Listener'
			proxycreds = 'ProxyCreds'
			required_computername = 'ComputerName'
			required_servicename = 'ServiceName'
			command = 'Command'
			proxy = 'Proxy'
			useragent = 'UserAgent'
			required_agent = 'Agent'
			resultfile = 'ResultFile'

	class invoke_executemsbuild(object):
		"""This module utilizes WMI and MSBuild to compile and execute an xml file containing an Empire launcher
		"""

		path = 'powershell/lateral_movement/invoke_executemsbuild'

		class options(object):
			username = 'UserName'
			credid = 'CredID'
			required_computername = 'ComputerName'
			driveletter = 'DriveLetter'
			proxycreds = 'ProxyCreds'
			filepath = 'FilePath'
			required_agent = 'Agent'
			required_listener = 'Listener'
			proxy = 'Proxy'
			useragent = 'UserAgent'
			password = 'Password'

