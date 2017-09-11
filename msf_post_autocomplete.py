""" This is generated autocomplete helper class for MSF """
class post(object):
	class windows_recon_resolve_ip(object):
		"""
		 This module reverse resolves a range or IP to a hostname
		"""

		path = 'windows/recon/resolve_ip'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			ADDRESS = 'ADDRESS'
			RANGE = 'RANGE'

	class windows_recon_outbound_ports(object):
		"""
		
        This module makes some kind of TCP traceroute to get outbound-filtering rules.
        It will try to make a TCP connection to a certain public IP address (this IP
        does not need to be under your control) using different TTL incremental values.
        This way if you get an answer (ICMP TTL time exceeded packet) from a public IP
        device you can infer that the destination port is allowed. Setting STOP to
        true the module will stop as soon as you reach a public IP (this will generate
        less noise in the network).
      
		"""

		path = 'windows/recon/outbound_ports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_ADDRESS = 'ADDRESS'
			required_HOPS = 'HOPS'
			required_MIN_TTL = 'MIN_TTL'
			required_PORTS = 'PORTS'
			required_TIMEOUT = 'TIMEOUT'
			required_STOP = 'STOP'

	class windows_recon_computer_browser_discovery(object):
		"""
		 This module uses railgun to discover hostnames and IPs on the network.
          LTYPE should be set to one of the following values: WK (all workstations), SVR (all servers),
          SQL (all SQL servers), DC (all Domain Controllers), DCBKUP (all Domain Backup Servers),
          NOVELL (all Novell servers), PRINTSVR (all Print Que servers), MASTERBROWSER (all Master Browswers),
          WINDOWS (all Windows hosts), or UNIX (all Unix hosts).
          
		"""

		path = 'windows/recon/computer_browser_discovery'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_LTYPE = 'LTYPE'
			DOMAIN = 'DOMAIN'
			required_SAVEHOSTS = 'SAVEHOSTS'

	class windows_manage_nbd_server(object):
		"""
		Maps remote disks and logical volumes to a local Network Block
        Device server. Allows for forensic tools to be executed on the remote disk directly.
		"""

		path = 'windows/manage/nbd_server'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DEVICE = 'DEVICE'
			NBDIP = 'NBDIP'
			NBDPORT = 'NBDPORT'

	class windows_manage_forward_pageant(object):
		"""
		
                         This module forwards SSH agent requests from a local socket to a remote Pageant instance.
                         If a target Windows machine is compromised and is running Pageant, this will allow the
                         attacker to run normal OpenSSH commands (e.g. ssh-add -l) against the Pageant host which are
                         tunnelled through the meterpreter session. This could therefore be used to authenticate
                         with a remote host using a private key which is loaded into a remote user's Pageant instance,
                         without ever having knowledge of the private key itself.

                         Note that this requires the PageantJacker meterpreter extension, but this will be automatically
                         loaded into the remote meterpreter session by this module if it is not already loaded.
                       
		"""

		path = 'windows/manage/forward_pageant'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SocketPath = 'SocketPath'

	class windows_manage_inject_host(object):
		"""
		
        This module allows the attacker to insert a new entry into the target
        system's hosts file.
      
		"""

		path = 'windows/manage/inject_host'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DOMAIN = 'DOMAIN'
			required_IP = 'IP'

	class windows_manage_powershell_build_net_code(object):
		"""
		
          This module will build a .NET source file using powershell. The compiler builds
          the executable or library in memory and produces a binary. After compilation the
          PowerShell session can also sign the executable if provided a path the
          a .pfx formatted certificate. Compiler options and a list of assemblies
          required can be configured in the datastore.
        
		"""

		path = 'windows/manage/powershell/build_net_code'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_Powershell_Post_timeout = 'Powershell::Post::timeout'
			required_Powershell_Post_log_output = 'Powershell::Post::log_output'
			required_Powershell_Post_dry_run = 'Powershell::Post::dry_run'
			required_Powershell_Post_force_wow64 = 'Powershell::Post::force_wow64'
			CERT_PATH = 'CERT_PATH'
			required_SOURCE_FILE = 'SOURCE_FILE'
			RUN_BINARY = 'RUN_BINARY'
			ASSEMBLIES = 'ASSEMBLIES'
			OUTPUT_TARGET = 'OUTPUT_TARGET'
			COMPILER_OPTS = 'COMPILER_OPTS'
			required_CODE_PROVIDER = 'CODE_PROVIDER'
			NET_CLR_VER = 'NET_CLR_VER'

	class windows_manage_powershell_exec_powershell(object):
		"""
		
        This module will download and execute a PowerShell script over a meterpreter session.
        The user may also enter text substitutions to be made in memory before execution.
        Setting VERBOSE to true will output both the script prior to execution and the results.
      
		"""

		path = 'windows/manage/powershell/exec_powershell'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_Powershell_Post_timeout = 'Powershell::Post::timeout'
			required_Powershell_Post_log_output = 'Powershell::Post::log_output'
			required_Powershell_Post_dry_run = 'Powershell::Post::dry_run'
			required_Powershell_Post_force_wow64 = 'Powershell::Post::force_wow64'
			required_SCRIPT = 'SCRIPT'
			SUBSTITUTIONS = 'SUBSTITUTIONS'
			DELETE = 'DELETE'
			DRY_RUN = 'DRY_RUN'
			TIMEOUT = 'TIMEOUT'

	class windows_manage_powershell_load_script(object):
		"""
		
        This module will download and execute one or more PowerShell script
        s over a present powershell session.
        Setting VERBOSE to true will show the stager results.
      
		"""

		path = 'windows/manage/powershell/load_script'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_Powershell_Post_timeout = 'Powershell::Post::timeout'
			required_Powershell_Post_log_output = 'Powershell::Post::log_output'
			required_Powershell_Post_dry_run = 'Powershell::Post::dry_run'
			required_Powershell_Post_force_wow64 = 'Powershell::Post::force_wow64'
			SCRIPT = 'SCRIPT'
			FOLDER = 'FOLDER'

	class windows_manage_pxeexploit(object):
		"""
		
        This module provides a PXE server, running a DHCP and TFTP server.
        The default configuration loads a linux kernel and initrd into memory that
        reads the hard drive; placing a payload to install metsvc, disable the
        firewall, and add a new user metasploit on any Windows partition seen,
        and add a uid 0 user with username and password metasploit to any linux
        partition seen. The windows user will have the password p@SSw0rd!123456
        (in case of complexity requirements) and will be added to the administrators
        group.

        See exploit/windows/misc/pxesploit for a version to deliver a specific payload.

        Note: the displayed IP address of a target is the address this DHCP server
        handed out, not the "normal" IP address the host uses.
      
		"""

		path = 'windows/manage/pxeexploit'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			TFTPROOT = 'TFTPROOT'
			SRVHOST = 'SRVHOST'
			NETMASK = 'NETMASK'
			required_RESETPXE = 'RESETPXE'
			DHCPIPSTART = 'DHCPIPSTART'
			DHCPIPEND = 'DHCPIPEND'

	class windows_manage_archmigrate(object):
		"""
		This module checks if the meterpreter architecture is the same as the OS architecture and if it's incompatible it spawns a
                          new process with the correct architecture and migrates into that process.
		"""

		path = 'windows/manage/archmigrate'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_EXE = 'EXE'
			required_FALLBACK = 'FALLBACK'

	class windows_manage_rpcapd_start(object):
		"""
		
          This module enables the Remote Packet Capture System (rpcapd service)
        included in the default installation of Winpcap. The module allows you to set up
        the service in passive or active mode (useful if the client is behind a firewall).
        If authentication is enabled you need a local user account to capture traffic.
        PORT will be used depending of the mode configured.
		"""

		path = 'windows/manage/rpcapd_start'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_NULLAUTH = 'NULLAUTH'
			required_ACTIVE = 'ACTIVE'
			RHOST = 'RHOST'
			required_PORT = 'PORT'

	class windows_manage_delete_user(object):
		"""
		
          This module deletes a local user account from the specified server,
        or the local machine if no server is given.
      
		"""

		path = 'windows/manage/delete_user'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_USERNAME = 'USERNAME'
			SERVER_NAME = 'SERVER_NAME'

	class windows_manage_vss_create(object):
		"""
		
        This module will attempt to create a new volume shadow copy.
        This is based on the VSSOwn Script originally posted by
        Tim Tomes and Mark Baggett.

        Works on win2k3 and later.
        
		"""

		path = 'windows/manage/vss_create'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SMBUser = 'SMBUser'
			SMBPass = 'SMBPass'
			SMBDomain = 'SMBDomain'
			required_RHOST = 'RHOST'
			required_TIMEOUT = 'TIMEOUT'
			required_VOLUME = 'VOLUME'

	class windows_manage_hashcarve(object):
		"""
		 This module will change a local user's password directly in the registry. 
		"""

		path = 'windows/manage/hashcarve'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_user = 'user'
			required_pass = 'pass'

	class windows_manage_run_as(object):
		"""
		
        This module will login with the specified username/password and execute the
        supplied command as a hidden process. Output is not returned by default, by setting
        CMDOUT to false output will be redirected to a temp file and read back in to
        display.By setting advanced option SETPASS to true, it will reset the users
        password and then execute the command.
                            
		"""

		path = 'windows/manage/run_as'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			EXE_EICAR = 'EXE::EICAR'
			EXE_Custom = 'EXE::Custom'
			EXE_Path = 'EXE::Path'
			EXE_Template = 'EXE::Template'
			EXE_Inject = 'EXE::Inject'
			EXE_OldMethod = 'EXE::OldMethod'
			EXE_FallBack = 'EXE::FallBack'
			MSI_EICAR = 'MSI::EICAR'
			MSI_Custom = 'MSI::Custom'
			MSI_Path = 'MSI::Path'
			MSI_Template = 'MSI::Template'
			MSI_UAC = 'MSI::UAC'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_DOMAIN = 'DOMAIN'
			required_USER = 'USER'
			required_PASSWORD = 'PASSWORD'
			required_CMD = 'CMD'
			required_CMDOUT = 'CMDOUT'
			required_SETPASS = 'SETPASS'

	class windows_manage_vss_mount(object):
		"""
		
        This module will attempt to mount a Volume Shadow Copy
        on the system. This is based on the VSSOwn Script
        originally posted by Tim Tomes and Mark Baggett.

        Works on win2k3 and later.
        
		"""

		path = 'windows/manage/vss_mount'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SMBUser = 'SMBUser'
			SMBPass = 'SMBPass'
			SMBDomain = 'SMBDomain'
			required_RHOST = 'RHOST'
			required_TIMEOUT = 'TIMEOUT'
			required_DEVICE = 'DEVICE'
			required_PATH = 'PATH'

	class windows_manage_reflective_dll_inject(object):
		"""
		
        This module will inject into the memory of a process a specified Reflective DLL.
      
		"""

		path = 'windows/manage/reflective_dll_inject'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_PATH = 'PATH'
			required_PID = 'PID'

	class windows_manage_multi_meterpreter_inject(object):
		"""
		 This module will inject in to several processes a given
        payload and connecting to a given list of IP Addresses.
        The module works with a given lists of IP Addresses and
        process PIDs if no PID is given it will start a the given
        process in the advanced options and inject the selected
        payload in to the memory of the created module.
		"""

		path = 'windows/manage/multi_meterpreter_inject'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			PAYLOAD = 'PAYLOAD'
			LPORT = 'LPORT'
			required_IPLIST = 'IPLIST'
			PIDLIST = 'PIDLIST'
			HANDLER = 'HANDLER'
			AMOUNT = 'AMOUNT'
			PROCESSNAME = 'PROCESSNAME'

	class windows_manage_sdel(object):
		"""
		
          The goal of the module is to hinder the recovery of deleted files by overwriting
        its contents.  This could be useful when you need to download some file on the victim
        machine and then delete it without leaving clues about its contents. Note that the script
        does not wipe the free disk space so temporary/sparse/encrypted/compressed files could
        not be overwritten. Note too that MTF entries are not overwritten so very small files
        could stay resident within the stream descriptor.
		"""

		path = 'windows/manage/sdel'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			ZERO = 'ZERO'
			ITERATIONS = 'ITERATIONS'
			required_FILE = 'FILE'

	class windows_manage_download_exec(object):
		"""
		
        This module will download a file by importing urlmon via railgun.
        The user may also choose to execute the file with arguments via exec_string.
      
		"""

		path = 'windows/manage/download_exec'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_URL = 'URL'
			DOWNLOAD_PATH = 'DOWNLOAD_PATH'
			FILENAME = 'FILENAME'
			required_OUTPUT = 'OUTPUT'
			required_EXECUTE = 'EXECUTE'
			EXEC_STRING = 'EXEC_STRING'
			required_EXEC_TIMEOUT = 'EXEC_TIMEOUT'
			required_DELETE = 'DELETE'

	class windows_manage_persistence_exe(object):
		"""
		
                            This Module will upload a executable to a remote host and make it Persistent.
                            It can be installed as USER, SYSTEM, or SERVICE. USER will start on user login,
                            SYSTEM will start on system boot but requires privs. SERVICE will create a new service
                            which will start the payload. Again requires privs.
                                             
		"""

		path = 'windows/manage/persistence_exe'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_STARTUP = 'STARTUP'
			required_REXEPATH = 'REXEPATH'
			required_REXENAME = 'REXENAME'

	class windows_manage_exec_powershell(object):
		"""
		
        This module will execute a powershell script in a meterpreter session.
        The user may also enter text substitutions to be made in memory before execution.
        Setting VERBOSE to true will output both the script prior to execution and the results.
      
		"""

		path = 'windows/manage/exec_powershell'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_Powershell_Post_timeout = 'Powershell::Post::timeout'
			required_Powershell_Post_log_output = 'Powershell::Post::log_output'
			required_Powershell_Post_dry_run = 'Powershell::Post::dry_run'
			required_Powershell_Post_force_wow64 = 'Powershell::Post::force_wow64'
			required_SCRIPT = 'SCRIPT'
			SUBSTITUTIONS = 'SUBSTITUTIONS'

	class windows_manage_pptp_tunnel(object):
		"""
		
          This module initiates a PPTP connection to a remote machine (VPN server). Once
        the tunnel is created we can use it to force the victim traffic to go through the
        server getting a man in the middle attack. Be sure to allow forwarding and
        masquerading on the VPN server (mitm).
      
		"""

		path = 'windows/manage/pptp_tunnel'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_USERNAME = 'USERNAME'
			required_PASSWORD = 'PASSWORD'
			required_MITM = 'MITM'
			required_TIMEOUT = 'TIMEOUT'
			required_PBK_NAME = 'PBK_NAME'
			required_VPNHOST = 'VPNHOST'

	class windows_manage_payload_inject(object):
		"""
		
        This module will inject into the memory of a process a specified windows payload.
        If a payload or process is not provided one will be created by default
        using a reverse x86 TCP Meterpreter Payload.
      
		"""

		path = 'windows/manage/payload_inject'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			PAYLOAD = 'PAYLOAD'
			required_LHOST = 'LHOST'
			LPORT = 'LPORT'
			PID = 'PID'
			HANDLER = 'HANDLER'
			OPTIONS = 'OPTIONS'
			AMOUNT = 'AMOUNT'

	class windows_manage_enable_rdp(object):
		"""
		
          This module enables the Remote Desktop Service (RDP). It provides the options to create
        an account and configure it to be a member of the Local Administrators and
        Remote Desktop Users group. It can also forward the target's port 3389/tcp.
		"""

		path = 'windows/manage/enable_rdp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			USERNAME = 'USERNAME'
			PASSWORD = 'PASSWORD'
			ENABLE = 'ENABLE'
			FORWARD = 'FORWARD'
			LPORT = 'LPORT'

	class windows_manage_change_password(object):
		"""
		
        This module will attempt to change the password of the targeted account.
        The typical usage is to change a newly created account's password on a
        remote host to avoid the error, 'System error 1907 has occurred,' which
        is caused when the account policy enforces a password change before the
        next login.
      
		"""

		path = 'windows/manage/change_password'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SMBDomain = 'SMBDomain'
			required_SMBUser = 'SMBUser'
			required_OLD_PASSWORD = 'OLD_PASSWORD'
			required_NEW_PASSWORD = 'NEW_PASSWORD'

	class windows_manage_enable_support_account(object):
		"""
		
        This module enables alternative access to servers and workstations
        by modifying the support account's properties. It will enable
        the account for remote access as the administrator user while
        taking advantage of some weird behavior in lusrmgr.msc. It will
        check if sufficient privileges are available for registry operations,
        otherwise it exits.
      
		"""

		path = 'windows/manage/enable_support_account'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_PASSWORD = 'PASSWORD'
			required_GETSYSTEM = 'GETSYSTEM'

	class windows_manage_wdigest_caching(object):
		"""
		
          On Windows 8/2012 or higher, the Digest Security Provider (WDIGEST) is disabled by default. This module enables/disables
          credential caching by adding/changing the value of the UseLogonCredential DWORD under the WDIGEST provider's Registry key.
          Any subsequest logins will allow mimikatz to recover the plain text passwords from the system's memory.
      
		"""

		path = 'windows/manage/wdigest_caching'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			ENABLE = 'ENABLE'

	class windows_manage_remove_ca(object):
		"""
		
        This module allows the attacker to remove an arbitrary CA certificate
        from the victim's Trusted Root store.
		"""

		path = 'windows/manage/remove_ca'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_CERTID = 'CERTID'

	class windows_manage_portproxy(object):
		"""
		
        This module uses the PortProxy interface from netsh to set up
        port forwarding persistently (even after reboot). PortProxy
        supports TCP IPv4 and IPv6 connections.
      
		"""

		path = 'windows/manage/portproxy'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_LOCAL_ADDRESS = 'LOCAL_ADDRESS'
			required_CONNECT_ADDRESS = 'CONNECT_ADDRESS'
			required_CONNECT_PORT = 'CONNECT_PORT'
			required_LOCAL_PORT = 'LOCAL_PORT'
			required_IPV6_XP = 'IPV6_XP'
			required_TYPE = 'TYPE'

	class windows_manage_vss_list(object):
		"""
		
        This module will attempt to list any Volume Shadow Copies
        on the system. This is based on the VSSOwn Script
        originally posted by Tim Tomes and Mark Baggett.

        Works on win2k3 and later.
        
		"""

		path = 'windows/manage/vss_list'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SMBUser = 'SMBUser'
			SMBPass = 'SMBPass'
			SMBDomain = 'SMBDomain'
			required_RHOST = 'RHOST'
			required_TIMEOUT = 'TIMEOUT'

	class windows_manage_vss_set_storage(object):
		"""
		
        This module will attempt to change the ammount of space
        for volume shadow copy storage. This is based on the
        VSSOwn Script originally posted by Tim Tomes and
        Mark Baggett.

        Works on win2k3 and later.
        
		"""

		path = 'windows/manage/vss_set_storage'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SMBUser = 'SMBUser'
			SMBPass = 'SMBPass'
			SMBDomain = 'SMBDomain'
			required_RHOST = 'RHOST'
			required_TIMEOUT = 'TIMEOUT'
			required_SIZE = 'SIZE'

	class windows_manage_remove_host(object):
		"""
		
        This module allows the attacker to remove an entry from the Windows hosts file.
      
		"""

		path = 'windows/manage/remove_host'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DOMAIN = 'DOMAIN'

	class windows_manage_migrate(object):
		"""
		 This module will migrate a Meterpreter session from one process
        to another. A given process PID to migrate to or the module can spawn one and
        migrate to that newly spawned process.
		"""

		path = 'windows/manage/migrate'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SPAWN = 'SPAWN'
			PID = 'PID'
			NAME = 'NAME'
			KILL = 'KILL'

	class windows_manage_inject_ca(object):
		"""
		
        This module allows the attacker to insert an arbitrary CA certificate
        into the victim's Trusted Root store.
      
		"""

		path = 'windows/manage/inject_ca'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_CAFILE = 'CAFILE'

	class windows_manage_vss_storage(object):
		"""
		
        This module will attempt to get volume shadow copy storage info.
        This is based on the VSSOwn Script originally posted by
        Tim Tomes and Mark Baggett.

        Works on win2k3 and later.
        
		"""

		path = 'windows/manage/vss_storage'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SMBUser = 'SMBUser'
			SMBPass = 'SMBPass'
			SMBDomain = 'SMBDomain'
			required_RHOST = 'RHOST'
			required_TIMEOUT = 'TIMEOUT'

	class windows_manage_autoroute(object):
		"""
		This module manages session routing via an existing
          Meterpreter session. It enables other modules to 'pivot' through a
          compromised host when connecting to the named NETWORK and SUBMASK.
          Autoadd will search a session for valid subnets from the routing table
          and interface list then add routes to them. Default will add a default
          route so that all TCP/IP traffic not specified in the MSF routing table
          will be routed through the session when pivoting. See documentation for more
          'info -d' and click 'Knowledge Base'
		"""

		path = 'windows/manage/autoroute'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SUBNET = 'SUBNET'
			NETMASK = 'NETMASK'
			required_CMD = 'CMD'

	class windows_manage_priv_migrate(object):
		"""
		 This module will migrate a Meterpreter session based on session privileges.
         It will do everything it can to migrate, including spawing a new User level process.
         For sessions with Admin rights: It will try to migrate into a System level process in the following
         order: ANAME (if specified), services.exe, wininit.exe, svchost.exe, lsm.exe, lsass.exe, and winlogon.exe.
         If all these fail and NOFAIL is set to true, it will fall back to User level migration. For sessions with User level rights:
         It will try to migrate to a user level process, if that fails it will attempt to spawn the process
         then migrate to it. It will attempt the User level processes in the following order:
         NAME (if specified), explorer.exe, then notepad.exe.
		"""

		path = 'windows/manage/priv_migrate'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			ANAME = 'ANAME'
			NAME = 'NAME'
			required_KILL = 'KILL'
			required_NOFAIL = 'NOFAIL'

	class windows_manage_mssql_local_auth_bypass(object):
		"""
		 When this module is executed, it can be used to add a sysadmin to local
        SQL Server instances.  It first attempts to gain LocalSystem privileges
        using the "getsystem" escalation methods. If those privileges are not
        sufficient to add a sysadmin, then it will migrate to the SQL Server
        service process associated with the target instance.  The sysadmin
        login is added to the local SQL Server using native SQL clients and
        stored procedures.  If no instance is specified then the first identified
        instance will be used.

        Why is this possible? By default in SQL Server 2k-2k8, LocalSystem
        is assigned syadmin privileges.  Microsoft changed the default in
        SQL Server 2012 so that LocalSystem no longer has sysadmin privileges.
        However, this can be overcome by migrating to the SQL Server process.
		"""

		path = 'windows/manage/mssql_local_auth_bypass'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DB_USERNAME = 'DB_USERNAME'
			required_DB_PASSWORD = 'DB_PASSWORD'
			INSTANCE = 'INSTANCE'
			required_REMOVE_LOGIN = 'REMOVE_LOGIN'

	class windows_manage_sticky_keys(object):
		"""
		
        This module makes it possible to apply the 'sticky keys' hack to a session with appropriate
        rights. The hack provides a means to get a SYSTEM shell using UI-level interaction at an RDP
        login screen or via a UAC confirmation dialog. The module modifies the Debug registry setting
        for certain executables.

        The module options allow for this hack to be applied to:

        SETHC   (sethc.exe is invoked when SHIFT is pressed 5 times),
        UTILMAN (Utilman.exe is invoked by pressing WINDOWS+U),
        OSK     (osk.exe is invoked by pressing WINDOWS+U, then launching the on-screen keyboard), and
        DISP    (DisplaySwitch.exe is invoked by pressing WINDOWS+P).

        The hack can be added using the ADD action, and removed with the REMOVE action.

        Custom payloads and binaries can be run as part of this exploit, but must be manually uploaded
        to the target prior to running the module. By default, a SYSTEM command prompt is installed
        using the registry method if this module is run without modifying any parameters.
      
		"""

		path = 'windows/manage/sticky_keys'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_TARGET = 'TARGET'
			required_EXE = 'EXE'

	class windows_manage_driver_loader(object):
		"""
		
        This module loads a KMD (Kernel Mode Driver) using the Windows Service API.
      
		"""

		path = 'windows/manage/driver_loader'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DRIVER_PATH = 'DRIVER_PATH'
			DRIVER_NAME = 'DRIVER_NAME'
			required_START_TYPE = 'START_TYPE'
			required_SERVICE_TYPE = 'SERVICE_TYPE'
			required_ERROR_TYPE = 'ERROR_TYPE'

	class windows_manage_add_user_domain(object):
		"""
		
              This module adds a user to the Domain and/or to a Domain group. It will
            check if sufficient privileges are present for certain actions and run
            getprivs for system.  If you elevated privs to system,the
            SeAssignPrimaryTokenPrivilege will not be assigned. You need to migrate to
            a process that is running as system. If you don't have privs, this script
            exits.
          
		"""

		path = 'windows/manage/add_user_domain'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_USERNAME = 'USERNAME'
			PASSWORD = 'PASSWORD'
			required_GROUP = 'GROUP'
			required_ADDTOGROUP = 'ADDTOGROUP'
			required_ADDTODOMAIN = 'ADDTODOMAIN'
			TOKEN = 'TOKEN'
			required_GETSYSTEM = 'GETSYSTEM'

	class windows_manage_clone_proxy_settings(object):
		"""
		
        This module copies the proxy settings from the current user to the
        targeted user SID, supports remote hosts as well if remote registry
        is allowed.
      
		"""

		path = 'windows/manage/clone_proxy_settings'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			RHOST = 'RHOST'
			SID = 'SID'

	class windows_manage_ie_proxypac(object):
		"""
		
        This module configures Internet Explorer to use a PAC proxy file. By using the LOCAL_PAC
        option, a PAC file will be created on the victim host. It's also possible to provide a
        remote PAC file (REMOTE_PAC option) by providing the full URL.
      
		"""

		path = 'windows/manage/ie_proxypac'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			LOCAL_PAC = 'LOCAL_PAC'
			REMOTE_PAC = 'REMOTE_PAC'
			required_DISABLE_PROXY = 'DISABLE_PROXY'
			required_AUTO_DETECT = 'AUTO_DETECT'

	class windows_manage_webcam(object):
		"""
		
          This module will allow the user to detect installed webcams (with
          the LIST action) or take a snapshot (with the SNAPSHOT) action.
      
		"""

		path = 'windows/manage/webcam'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			INDEX = 'INDEX'
			QUALITY = 'QUALITY'

	class windows_manage_run_as_psh(object):
		"""
		 This module will start a process as another user using powershell. 
		"""

		path = 'windows/manage/run_as_psh'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_Powershell_Post_timeout = 'Powershell::Post::timeout'
			required_Powershell_Post_log_output = 'Powershell::Post::log_output'
			required_Powershell_Post_dry_run = 'Powershell::Post::dry_run'
			required_Powershell_Post_force_wow64 = 'Powershell::Post::force_wow64'
			required_USER = 'USER'
			required_PASS = 'PASS'
			DOMAIN = 'DOMAIN'
			required_EXE = 'EXE'
			ARGS = 'ARGS'
			required_PATH = 'PATH'
			required_CHANNELIZE = 'CHANNELIZE'
			required_INTERACTIVE = 'INTERACTIVE'
			required_HIDDEN = 'HIDDEN'

	class windows_manage_killav(object):
		"""
		
        This module attempts to locate and terminate any processes that are identified
        as being Antivirus or Host-based IPS related.
      
		"""

		path = 'windows/manage/killav'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_escalate_golden_ticket(object):
		"""
		
          This module will create a Golden Kerberos Ticket using the Mimikatz Kiwi Extension. If no
        options are applied it will attempt to identify the current domain, the domain administrator
        account, the target domain SID, and retrieve the krbtgt NTLM hash from the database. By default
        the well-known Administrator's groups 512, 513, 518, 519, and 520 will be applied to the ticket.
        
		"""

		path = 'windows/escalate/golden_ticket'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_USE = 'USE'
			USER = 'USER'
			DOMAIN = 'DOMAIN'
			KRBTGT_HASH = 'KRBTGT_HASH'
			Domain_SID = 'Domain SID'
			ID = 'ID'
			GROUPS = 'GROUPS'

	class windows_escalate_droplnk(object):
		"""
		
          This module drops a shortcut (LNK file) that has a ICON reference
          existing on the specified remote host, causing SMB and WebDAV
          connections to be initiated from any user that views the shortcut.
        
		"""

		path = 'windows/escalate/droplnk'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_LHOST = 'LHOST'
			required_LNKFILENAME = 'LNKFILENAME'
			required_SHARENAME = 'SHARENAME'
			required_ICONFILENAME = 'ICONFILENAME'

	class windows_escalate_getsystem(object):
		"""
		
          This module uses the builtin 'getsystem' command to escalate
        the current session to the SYSTEM account from an administrator
        user account.
      
		"""

		path = 'windows/escalate/getsystem'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			TECHNIQUE = 'TECHNIQUE'

	class windows_escalate_screen_unlock(object):
		"""
		
          This module unlocks a locked Windows desktop by patching
        the respective code inside the LSASS.exe process. This
        patching process can result in the target system hanging or
        even rebooting, so be careful when using this module on
        production systems.
      
		"""

		path = 'windows/escalate/screen_unlock'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			REVERT = 'REVERT'

	class windows_escalate_ms10_073_kbdlayout(object):
		"""
		
          This module exploits the keyboard layout vulnerability exploited by Stuxnet. When
        processing specially crafted keyboard layout files (DLLs), the Windows kernel fails
        to validate that an array index is within the bounds of the array. By loading
        a specially crafted keyboard layout, an attacker can execute code in Ring 0.
      
		"""

		path = 'windows/escalate/ms10_073_kbdlayout'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_wlan_wlan_profile(object):
		"""
		
        This module extracts saved Wireless LAN profiles. It will also try to decrypt
        the network key material. Behaviour is slightly different bewteen OS versions
        when it comes to WPA. In Windows Vista/7 we will get the passphrase. In
        Windows XP we will get the PBKDF2 derived key.
      
		"""

		path = 'windows/wlan/wlan_profile'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_wlan_wlan_bss_list(object):
		"""
		
        This module gathers information about the wireless Basic Service Sets
        available to the victim machine.
        
		"""

		path = 'windows/wlan/wlan_bss_list'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_wlan_wlan_disconnect(object):
		"""
		
        This module disconnects the current wireless network connection
        on the specified interface.
      
		"""

		path = 'windows/wlan/wlan_disconnect'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Interface = 'Interface'

	class windows_wlan_wlan_current_connection(object):
		"""
		
        This module gathers information about the current connection on each
        wireless lan interface on the target machine.
      
		"""

		path = 'windows/wlan/wlan_current_connection'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_capture_lockout_keylogger(object):
		"""
		
          This module migrates and logs Microsoft Windows user's passwords via
          Winlogon.exe using idle time and natural system changes to give a
          false sense of security to the user.
		"""

		path = 'windows/capture/lockout_keylogger'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_INTERVAL = 'INTERVAL'
			required_HEARTBEAT = 'HEARTBEAT'
			required_LOCKTIME = 'LOCKTIME'
			PID = 'PID'
			required_WAIT = 'WAIT'

	class windows_capture_keylog_recorder(object):
		"""
		
          This module can be used to capture keystrokes. To capture keystrokes when the session is running
          as SYSTEM, the MIGRATE option must be enabled and the CAPTURE_TYPE option should be set to one of
          Explorer, Winlogon, or a specific PID. To capture the keystrokes of the interactive user, the
          Explorer option should be used with MIGRATE enabled. Keep in mind that this will demote this session
          to the user's privileges, so it makes sense to create a separate session for this task. The Winlogon
          option will capture the username and password entered into the logon and unlock dialog. The LOCKSCREEN
          option can be combined with the Winlogon CAPTURE_TYPE to for the user to enter their clear-text
          password. It is recommended to run this module as a job, otherwise it will tie up your framework user interface.
            
		"""

		path = 'windows/capture/keylog_recorder'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			LOCKSCREEN = 'LOCKSCREEN'
			MIGRATE = 'MIGRATE'
			INTERVAL = 'INTERVAL'
			PID = 'PID'
			CAPTURE_TYPE = 'CAPTURE_TYPE'
			ShowKeystrokes = 'ShowKeystrokes'
			required_TimeOutAction = 'TimeOutAction'

	class windows_gather_enum_chrome(object):
		"""
		
        This module will collect user data from Google Chrome and attempt to decrypt
        sensitive information.
      
		"""

		path = 'windows/gather/enum_chrome'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			MIGRATE = 'MIGRATE'

	class windows_gather_enum_db(object):
		"""
		 This module will enumerate a windows system for installed database instances 
		"""

		path = 'windows/gather/enum_db'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_dnscache_dump(object):
		"""
		 This module displays the records stored in the DNS cache.
		"""

		path = 'windows/gather/dnscache_dump'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_powershell_env(object):
		"""
		 This module will enumerate Microsoft Powershell settings 
		"""

		path = 'windows/gather/enum_powershell_env'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_av_excluded(object):
		"""
		
          This module will enumerate the file, directory, process and
          extension-based exclusions from supported AV products, which
          currently includes Microsoft Defender, Microsoft Security
          Essentials/Antimalware, and Symantec Endpoint Protection.
        
		"""

		path = 'windows/gather/enum_av_excluded'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DEFENDER = 'DEFENDER'
			required_ESSENTIALS = 'ESSENTIALS'
			required_SEP = 'SEP'

	class windows_gather_outlook(object):
		"""
		
        This module allows reading and searching email messages from the local
        Outlook installation using PowerShell. Please note that this module is
        manipulating the victims keyboard/mouse.  If a victim is active on the target
        system, he may notice the activities of this module. Tested on Windows 8.1
        x64 with Office 2013.
      
		"""

		path = 'windows/gather/outlook'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_Powershell_Post_timeout = 'Powershell::Post::timeout'
			required_Powershell_Post_log_output = 'Powershell::Post::log_output'
			required_Powershell_Post_dry_run = 'Powershell::Post::dry_run'
			required_Powershell_Post_force_wow64 = 'Powershell::Post::force_wow64'
			FOLDER = 'FOLDER'
			KEYWORD = 'KEYWORD'
			A_TRANSLATION = 'A_TRANSLATION'
			ACF_TRANSLATION = 'ACF_TRANSLATION'
			required_TIMEOUT = 'TIMEOUT'

	class windows_gather_enum_ad_user_comments(object):
		"""
		
          This module will enumerate user accounts in the default Active Domain (AD) directory which
        contain 'pass' in their description or comment (case-insensitive) by default. In some cases,
        such users have their passwords specified in these fields.
        
		"""

		path = 'windows/gather/enum_ad_user_comments'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_STORE_LOOT = 'STORE_LOOT'
			required_FIELDS = 'FIELDS'
			required_FILTER = 'FILTER'

	class windows_gather_netlm_downgrade(object):
		"""
		 This module will change a registry value to enable
        the sending of LM challenge hashes and then initiate a SMB connection to
        the SMBHOST datastore. If an SMB server is listening, it will receive the
        NetLM hashes
        
		"""

		path = 'windows/gather/netlm_downgrade'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_SMBHOST = 'SMBHOST'

	class windows_gather_make_csv_orgchart(object):
		"""
		
        This module will generate a CSV file containing all users and their managers, which can be
        imported into Visio which will render it.
            
		"""

		path = 'windows/gather/make_csv_orgchart'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_WITH_MANAGERS_ONLY = 'WITH_MANAGERS_ONLY'
			required_ACTIVE_USERS_ONLY = 'ACTIVE_USERS_ONLY'
			required_STORE_LOOT = 'STORE_LOOT'
			FILTER = 'FILTER'

	class windows_gather_enum_snmp(object):
		"""
		 This module will enumerate the SNMP service configuration 
		"""

		path = 'windows/gather/enum_snmp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_ntds_location(object):
		"""
		
        This module will find the location of the NTDS.DIT file (from the Registry),
        check that it exists, and display its location on the screen, which is useful
        if you wish to manually acquire the file using ntdsutil or vss.
      
		"""

		path = 'windows/gather/ntds_location'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_usb_history(object):
		"""
		 This module will enumerate USB Drive history on a target host.
		"""

		path = 'windows/gather/usb_history'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_ad_groups(object):
		"""
		
        This module will enumerate AD groups on the specified domain.
            
		"""

		path = 'windows/gather/enum_ad_groups'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			ADDITIONAL_FIELDS = 'ADDITIONAL_FIELDS'
			FILTER = 'FILTER'

	class windows_gather_enum_ad_bitlocker(object):
		"""
		
        This module will enumerate BitLocker recovery passwords in the default AD
        directory. This module does require Domain Admin or other delegated privileges.
      
		"""

		path = 'windows/gather/enum_ad_bitlocker'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_STORE_LOOT = 'STORE_LOOT'
			required_FIELDS = 'FIELDS'
			required_FILTER = 'FILTER'

	class windows_gather_enum_unattend(object):
		"""
		
          This module will check the file system for a copy of unattend.xml and/or
        autounattend.xml found in Windows Vista, or newer Windows systems.  And then
        extract sensitive information such as usernames and decoded passwords.
      
		"""

		path = 'windows/gather/enum_unattend'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_GETALL = 'GETALL'

	class windows_gather_hashdump(object):
		"""
		 This module will dump the local user accounts from the SAM database using the registry 
		"""

		path = 'windows/gather/hashdump'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_patches(object):
		"""
		
          This module will attempt to enumerate which patches are applied to a windows system
          based on the result of the WMI query: SELECT HotFixID FROM Win32_QuickFixEngineering
        
		"""

		path = 'windows/gather/enum_patches'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_MSFLOCALS = 'MSFLOCALS'
			required_KB = 'KB'

	class windows_gather_win_privs(object):
		"""
		
        This module will print if UAC is enabled, and if the current account is
        ADMIN enabled. It will also print UID, foreground SESSION ID, is SYSTEM status
        and current process PRIVILEGES.
      
		"""

		path = 'windows/gather/win_privs'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_devices(object):
		"""
		
          Enumerate PCI hardware information from the registry. Please note this script
        will run through registry subkeys such as: 'PCI', 'ACPI', 'ACPI_HAL', 'FDC', 'HID',
        'HTREE', 'IDE', 'ISAPNP', 'LEGACY'', LPTENUM', 'PCIIDE', 'SCSI', 'STORAGE', 'SW',
        and 'USB'; it will take time to finish. It is recommended to run this module as a
        background job.
        
		"""

		path = 'windows/gather/enum_devices'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_tokens(object):
		"""
		
          This module will identify systems that have a Domain Admin (delegation) token
          on them.  The module will first check if sufficient privileges are present for
          certain actions, and run getprivs for system.  If you elevated privs to system,
          the SeAssignPrimaryTokenPrivilege will not be assigned, in that case try
          migrating to another process that is running as system.  If no sufficient
          privileges are available, the script will not continue.
        
		"""

		path = 'windows/gather/enum_tokens'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_GETSYSTEM = 'GETSYSTEM'

	class windows_gather_enum_proxy(object):
		"""
		
        This module pulls a user's proxy settings. If neither RHOST or SID
        are set it pulls the current user, else it will pull the user's settings
        specified SID and target host.
      
		"""

		path = 'windows/gather/enum_proxy'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			RHOST = 'RHOST'
			SID = 'SID'

	class windows_gather_enum_applications(object):
		"""
		 This module will enumerate all installed applications 
		"""

		path = 'windows/gather/enum_applications'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_arp_scanner(object):
		"""
		 This Module will perform an ARP scan for a given IP range through a
          Meterpreter Session.
		"""

		path = 'windows/gather/arp_scanner'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_RHOSTS = 'RHOSTS'
			THREADS = 'THREADS'

	class windows_gather_enum_prefetch(object):
		"""
		
        This module gathers prefetch file information from WinXP, Win2k3 and Win7 systems
        and current values of related registry keys. From each prefetch file we'll collect
        filetime (converted to utc) of the last execution, file path hash, run count, filename
        and the execution path.
      
		"""

		path = 'windows/gather/enum_prefetch'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_lsa_secrets(object):
		"""
		
        This module will attempt to enumerate the LSA Secrets keys within the registry. The registry value used is:
        HKEY_LOCAL_MACHINE/Security/Policy/Secrets/. Thanks goes to Maurizio Agazzini and Mubix for decrypt
        code from cachedump.
        
		"""

		path = 'windows/gather/lsa_secrets'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_forensics_nbd_server(object):
		"""
		
          Maps remote disks and logical volumes to a local Network Block Device server.
        Allows for forensic tools to be executed on the remote disk directly.
      
		"""

		path = 'windows/gather/forensics/nbd_server'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DEVICE = 'DEVICE'
			NBDIP = 'NBDIP'
			NBDPORT = 'NBDPORT'

	class windows_gather_forensics_duqu_check(object):
		"""
		 This module searches for CVE-2011-3402 (Duqu) related registry artifacts.
		"""

		path = 'windows/gather/forensics/duqu_check'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_forensics_enum_drives(object):
		"""
		This module will list physical drives and logical volumes
		"""

		path = 'windows/gather/forensics/enum_drives'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			MAXDRIVES = 'MAXDRIVES'

	class windows_gather_forensics_imager(object):
		"""
		This module will perform byte-for-byte imaging of remote disks and volumes
		"""

		path = 'windows/gather/forensics/imager'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DEVICE = 'DEVICE'
			OUTFILE = 'OUTFILE'
			SPLIT = 'SPLIT'
			BLOCKSIZE = 'BLOCKSIZE'
			SKIP = 'SKIP'
			COUNT = 'COUNT'

	class windows_gather_forensics_recovery_files(object):
		"""
		
        This module lists and attempts to recover deleted files from NTFS file systems. Use
        the FILES option to guide recovery. Leave this option empty to enumerate deleted files in the
        DRIVE. Set FILES to an extension (e.g., "pdf") to recover deleted files with that
        extension, or set FILES to a comma separated list of IDs (from enumeration) to
        recover those files. The user must have account file enumeration. Recovery
        may take a long time; use the TIMEOUT option to abort enumeration or recovery by
        extension after a specified period (in seconds).
      
		"""

		path = 'windows/gather/forensics/recovery_files'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			FILES = 'FILES'
			required_DRIVE = 'DRIVE'
			required_TIMEOUT = 'TIMEOUT'

	class windows_gather_forensics_browser_history(object):
		"""
		
          Gathers Skype chat logs, Firefox history, and Chrome history data from the target machine.
        
		"""

		path = 'windows/gather/forensics/browser_history'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_termserv(object):
		"""
		
        This module dumps MRU and connection data for RDP sessions
      
		"""

		path = 'windows/gather/enum_termserv'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_computers(object):
		"""
		
            This module will enumerate computers included in the primary Domain.
        
		"""

		path = 'windows/gather/enum_computers'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_ad_service_principal_names(object):
		"""
		
        This module will enumerate servicePrincipalName in the default AD directory
        where the user is a member of the Domain Admins group.
      
		"""

		path = 'windows/gather/enum_ad_service_principal_names'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_FILTER = 'FILTER'

	class windows_gather_enum_ad_to_wordlist(object):
		"""
		
        This module will gather information from the default Active Domain (AD) directory
        and use these words to seed a wordlist. By default it enumerates user accounts to
        build the wordlist.
      
		"""

		path = 'windows/gather/enum_ad_to_wordlist'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_FIELDS = 'FIELDS'
			required_FILTER = 'FILTER'

	class windows_gather_enum_ad_computers(object):
		"""
		
            This module will enumerate computers in the default AD directory.

            Optional Attributes to use in ATTRIBS:
            objectClass, cn, description, distinguishedName, instanceType, whenCreated,
            whenChanged, uSNCreated, uSNChanged, name, objectGUID,
            userAccountControl, badPwdCount, codePage, countryCode,
            badPasswordTime, lastLogoff, lastLogon, localPolicyFlags,
            pwdLastSet, primaryGroupID, objectSid, accountExpires,
            logonCount, sAMAccountName, sAMAccountType, operatingSystem,
            operatingSystemVersion, operatingSystemServicePack, serverReferenceBL,
            dNSHostName, rIDSetPreferences, servicePrincipalName, objectCategory,
            netbootSCPBL, isCriticalSystemObject, frsComputerReferenceBL,
            lastLogonTimestamp, msDS-SupportedEncryptionTypes

            ActiveDirectory has a MAX_SEARCH limit of 1000 by default. Split search up
            if you hit that limit.

            Possible filters:
            (objectClass=computer) # All Computers
            (primaryGroupID=516)  # All Domain Controllers
            (&(objectCategory=computer)(operatingSystem=*server*)) # All Servers
        
		"""

		path = 'windows/gather/enum_ad_computers'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_STORE_LOOT = 'STORE_LOOT'
			required_STORE_DB = 'STORE_DB'
			required_FIELDS = 'FIELDS'
			required_FILTER = 'FILTER'

	class windows_gather_enum_ms_product_keys(object):
		"""
		 This module will enumerate the OS license key 
		"""

		path = 'windows/gather/enum_ms_product_keys'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_emet(object):
		"""
		 This module will enumerate the EMET protected paths on the target host.
		"""

		path = 'windows/gather/enum_emet'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_domain_tokens(object):
		"""
		
            This module will enumerate tokens present on a system that are part of the
            domain the target host is part of, will also enumerate users in the local
            Administrators, Users and Backup Operator groups to identify Domain members.
            Processes will be also enumerated and checked if they are running under a
            Domain account, on all checks the accounts, processes and tokens will be
            checked if they are part of the Domain Admin group of the domain the machine
            is a member of.
        
		"""

		path = 'windows/gather/enum_domain_tokens'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_cachedump(object):
		"""
		
        This module uses the registry to extract the stored domain hashes that have been
        cached as a result of a GPO setting. The default setting on Windows is to store
        the last ten successful logins.
		"""

		path = 'windows/gather/cachedump'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_logged_on_users(object):
		"""
		 This module will enumerate current and recently logged on Windows users
		"""

		path = 'windows/gather/enum_logged_on_users'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_CURRENT = 'CURRENT'
			required_RECENT = 'RECENT'

	class windows_gather_memory_grep(object):
		"""
		
          This module allows for searching the memory space of a proccess for potentially
        sensitive data.  Please note: When the HEAP option is enabled, the module will have
        to migrate to the process you are grepping, and will not migrate back automatically.
        This means that if the user terminates the application after using this module, you
        may lose your session.
      
		"""

		path = 'windows/gather/memory_grep'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_PROCESS = 'PROCESS'
			required_REGEX = 'REGEX'
			HEAP = 'HEAP'

	class windows_gather_enum_ad_managedby_groups(object):
		"""
		
        This module will enumerate AD groups on the specified domain which are specifically managed.
        It cannot at the moment identify whether the 'Manager can update membership list' option
        option set; if so, it would allow that member to update the contents of that group. This
        could either be used as a persistence mechanism (for example, set your user as the 'Domain
        Admins' group manager) or could be used to detect privilege escalation opportunities
        without having domain admin privileges.
      
		"""

		path = 'windows/gather/enum_ad_managedby_groups'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			ADDITIONAL_FIELDS = 'ADDITIONAL_FIELDS'
			required_RESOLVE_MANAGERS = 'RESOLVE_MANAGERS'
			required_SECURITY_GROUPS_ONLY = 'SECURITY_GROUPS_ONLY'

	class windows_gather_enum_hostfile(object):
		"""
		
        This module returns a list of entries in the target system's hosts file.
      
		"""

		path = 'windows/gather/enum_hostfile'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_phish_windows_credentials(object):
		"""
		
                This module is able to perform a phishing attack on the target by popping up a loginprompt.
                When the user fills credentials in the loginprompt, the credentials will be sent to the attacker.
                The module is able to monitor for new processes and popup a loginprompt when a specific process is starting. Tested on Windows 7.
      
		"""

		path = 'windows/gather/phish_windows_credentials'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_Powershell_persist = 'Powershell::persist'
			Powershell_prepend_sleep = 'Powershell::prepend_sleep'
			required_Powershell_strip_comments = 'Powershell::strip_comments'
			required_Powershell_strip_whitespace = 'Powershell::strip_whitespace'
			required_Powershell_sub_vars = 'Powershell::sub_vars'
			required_Powershell_sub_funcs = 'Powershell::sub_funcs'
			required_Powershell_exec_in_place = 'Powershell::exec_in_place'
			required_Powershell_encode_final_payload = 'Powershell::encode_final_payload'
			required_Powershell_encode_inner_payload = 'Powershell::encode_inner_payload'
			required_Powershell_use_single_quotes = 'Powershell::use_single_quotes'
			required_Powershell_no_equals = 'Powershell::no_equals'
			required_Powershell_method = 'Powershell::method'
			required_Powershell_Post_timeout = 'Powershell::Post::timeout'
			required_Powershell_Post_log_output = 'Powershell::Post::log_output'
			required_Powershell_Post_dry_run = 'Powershell::Post::dry_run'
			required_Powershell_Post_force_wow64 = 'Powershell::Post::force_wow64'
			PROCESS = 'PROCESS'
			required_DESCRIPTION = 'DESCRIPTION'
			required_TIMEOUT = 'TIMEOUT'

	class windows_gather_credentials_gpp(object):
		"""
		
        This module enumerates the victim machine's domain controller and
        connects to it via SMB. It then looks for Group Policy Preference XML
        files containing local user accounts and passwords and decrypts them
        using Microsofts public AES key.

        Cached Group Policy files may be found on end-user devices if the group
        policy object is deleted rather than unlinked.

        Tested on WinXP SP3 Client and Win2k8 R2 DC.
      
		"""

		path = 'windows/gather/credentials/gpp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			ALL = 'ALL'
			STORE = 'STORE'
			DOMAINS = 'DOMAINS'

	class windows_gather_credentials_ftpnavigator(object):
		"""
		
        This module extracts saved passwords from the FTP Navigator FTP client.
        It will decode the saved passwords and store them in the database.
      
		"""

		path = 'windows/gather/credentials/ftpnavigator'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_smartermail(object):
		"""
		
        This module extracts and decrypts the sysadmin password in the
        SmarterMail 'mailConfig.xml' configuration file. The encryption
        key and IV are publicly known.

        This module has been tested successfully on SmarterMail versions
        10.7.4842 and 11.7.5136.
      
		"""

		path = 'windows/gather/credentials/smartermail'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_outlook(object):
		"""
		
          This module extracts and decrypts saved Microsoft
          Outlook (versions 2002-2010) passwords from the Windows
          Registry for POP3/IMAP/SMTP/HTTP accounts.
          In order for decryption to be successful, this module must be
          executed under the same privileges as the user which originally
          encrypted the password.
        
		"""

		path = 'windows/gather/credentials/outlook'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_tortoisesvn(object):
		"""
		
          This module extracts and decrypts saved TortoiseSVN passwords.  In
          order for decryption to be successful this module must be executed
          under the same privileges as the user which originally encrypted the
          password.
        
		"""

		path = 'windows/gather/credentials/tortoisesvn'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_total_commander(object):
		"""
		
          This module extracts weakly encrypted saved FTP Passwords from Total Commander.
          It finds saved FTP connections in the wcx_ftp.ini file.
        
		"""

		path = 'windows/gather/credentials/total_commander'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_trillian(object):
		"""
		
        This module extracts account password from Trillian & Trillian Astra
        v4.x-5.x instant messenger.
      
		"""

		path = 'windows/gather/credentials/trillian'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_enum_laps(object):
		"""
		
        This module will recover the LAPS (Local Administrator Password Solution) passwords,
        configured in Active Directory, which is usually only accessible by privileged users.
        Note that the local administrator account name is not stored in Active Directory,
        so it is assumed to be 'Administrator' by default.
      
		"""

		path = 'windows/gather/credentials/enum_laps'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_LOCAL_ADMIN_NAME = 'LOCAL_ADMIN_NAME'
			required_STORE_DB = 'STORE_DB'
			required_STORE_LOOT = 'STORE_LOOT'
			required_FILTER = 'FILTER'

	class windows_gather_credentials_idm(object):
		"""
		
          This module recovers the saved premium download account passwords from
        Internet Download Manager (IDM). These passwords are stored in an encoded
        format in the registry. This module traverses through these registry entries
        and decodes them. Thanks to the template code of theLightCosine's CoreFTP
        password module.
      
		"""

		path = 'windows/gather/credentials/idm'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_filezilla_server(object):
		"""
		 This module will collect credentials from the FileZilla FTP server if installed. 
		"""

		path = 'windows/gather/credentials/filezilla_server'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SSLCERT = 'SSLCERT'

	class windows_gather_credentials_imail(object):
		"""
		
          This module will collect iMail user data such as the username, domain,
        full name, e-mail, and the decoded password.  Please note if IMAILUSER is
        specified, the module extracts user data from all the domains found.  If
        IMAILDOMAIN is specified, then it will extract all user data under that
        particular category.
      
		"""

		path = 'windows/gather/credentials/imail'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			IMAILUSER = 'IMAILUSER'
			IMAILDOMAIN = 'IMAILDOMAIN'

	class windows_gather_credentials_flashfxp(object):
		"""
		
        This module extracts weakly encrypted saved FTP Passwords  from FlashFXP. It
        finds saved FTP connections in the Sites.dat file. 
		"""

		path = 'windows/gather/credentials/flashfxp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_credential_collector(object):
		"""
		 This module harvests credentials found on the host and stores them in the database.
		"""

		path = 'windows/gather/credentials/credential_collector'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_dyndns(object):
		"""
		
          This module extracts the username, password, and hosts for DynDNS version 4.1.8.
        This is done by downloading the config.dyndns file from the victim machine, and then
        automatically decode the password field. The original copy of the config file is also
        saved to disk.
      
		"""

		path = 'windows/gather/credentials/dyndns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_spark_im(object):
		"""
		
            This module will enumerate passwords stored by the Spark IM client.
          The encryption key is publicly known. This module will not only extract encrypted
          password but will also decrypt password using public key.
        
		"""

		path = 'windows/gather/credentials/spark_im'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_vnc(object):
		"""
		
          This module extract DES encrypted passwords in known VNC locations
        
		"""

		path = 'windows/gather/credentials/vnc'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_skype(object):
		"""
		 This module finds saved login credentials
            for the Windows Skype client. The hash is in MD5 format
            that uses the username, a static string "/nskyper/n" and the
            password. The resulting MD5 is stored in the Config.xml file
            for the user after being XOR'd against a key generated by applying
            2 SHA1 hashes of "salt" data which is stored in ProtectedStorage
            using the Windows API CryptProtectData against the MD5 
		"""

		path = 'windows/gather/credentials/skype'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_enum_cred_store(object):
		"""
		
          This module will enumerate the Microsoft Credential Store and decrypt the
        credentials. This module can only access credentials created by the user the
        process is running as.  It cannot decrypt Domain Network Passwords, but will
        display the username and location.
      
		"""

		path = 'windows/gather/credentials/enum_cred_store'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_meebo(object):
		"""
		
            This module extracts login account password stored by
            Meebo Notifier, a desktop version of Meebo's Online Messenger.
		"""

		path = 'windows/gather/credentials/meebo'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_epo_sql(object):
		"""
		
        This module extracts connection details and decrypts the saved password for the
        SQL database in use by a McAfee ePO 4.6 server. The passwords are stored in a
        config file. They are encrypted with AES-128-ECB and a static key.
      
		"""

		path = 'windows/gather/credentials/epo_sql'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_imvu(object):
		"""
		
        This module extracts account username & password from the IMVU game client
        and stores it as loot.
        
		"""

		path = 'windows/gather/credentials/imvu'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_coreftp(object):
		"""
		
        This module extracts saved passwords from the CoreFTP FTP client. These
      passwords are stored in the registry. They are encrypted with AES-128-ECB.
      This module extracts and decrypts these passwords.
      
		"""

		path = 'windows/gather/credentials/coreftp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_rdc_manager_creds(object):
		"""
		
          This module extracts and decrypts saved Microsoft Remote Desktop
          Connection Manager (RDCMan) passwords the .RDG files of users.
          The module will attempt to find the files configured for all users
          on the target system. Passwords for managed hosts are encrypted by
          default.  In order for decryption of these passwords to be successful,
          this module must be executed under the same account as the user which
          originally encrypted the password.  Passwords stored in plain text will
          be captured and documented.
        
		"""

		path = 'windows/gather/credentials/rdc_manager_creds'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_sso(object):
		"""
		
        This module will collect cleartext Single Sign On credentials from the Local
      Security Authority using the Mimikatz extension. Blank passwords will not be stored
      in the database.
          
		"""

		path = 'windows/gather/credentials/sso'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_mcafee_vse_hashdump(object):
		"""
		
        This module extracts the password hash from McAfee Virus Scan Enterprise (VSE)
        used to lock down the user interface. Hashcat supports cracking this type of
        hash using hash type sha1($salt.unicode($pass)) (-m 140) and a hex salt
        (--hex-salt) of 01000f000d003300 (unicode "/x01/x0f/x0d/x33"). A dynamic
        format is available for John the Ripper at the referenced URL.
      
		"""

		path = 'windows/gather/credentials/mcafee_vse_hashdump'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_enum_picasa_pwds(object):
		"""
		
          This module extracts and decrypts the login passwords
          stored by Google Picasa.
        
		"""

		path = 'windows/gather/credentials/enum_picasa_pwds'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_domain_hashdump(object):
		"""
		
        This module attempts to copy the NTDS.dit database from a live Domain Controller
        and then parse out all of the User Accounts. It saves all of the captured password
        hashes, including historical ones.
  
		"""

		path = 'windows/gather/credentials/domain_hashdump'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_RHOST = 'RHOST'
			required_TIMEOUT = 'TIMEOUT'

	class windows_gather_credentials_smartftp(object):
		"""
		 This module finds saved login credentials
            for the SmartFTP FTP client for windows.
            It finds the saved passwords and decrypts
            them.
		"""

		path = 'windows/gather/credentials/smartftp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_mssql_local_hashdump(object):
		"""
		 This module extracts the usernames and password
        hashes from an MSSQL server and stores them as loot. It uses the
        same technique in mssql_local_auth_bypass.
        
		"""

		path = 'windows/gather/credentials/mssql_local_hashdump'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			INSTANCE = 'INSTANCE'

	class windows_gather_credentials_nimbuzz(object):
		"""
		
          This module extracts the account passwords saved by Nimbuzz Instant
        Messenger in hex format.
      
		"""

		path = 'windows/gather/credentials/nimbuzz'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_razer_synapse(object):
		"""
		
          This module will enumerate passwords stored by the Razer Synapse
          client. The encryption key and iv is publicly known. This module
          will not only extract encrypted password but will also decrypt
          password using public key. Affects versions earlier than 1.7.15.
        
		"""

		path = 'windows/gather/credentials/razer_synapse'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_dynazip_log(object):
		"""
		
        This module extracts clear text credentials from dynazip.log.
        The log file contains passwords used to encrypt compressed zip
        files in Microsoft Plus! 98 and Windows Me.
      
		"""

		path = 'windows/gather/credentials/dynazip_log'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_windows_autologin(object):
		"""
		
          This module extracts the plain-text Windows user login password in Registry.
          It exploits a Windows feature that Windows (2000 to 2008 R2) allows a
          user or third-party Windows Utility tools to configure User AutoLogin via
          plain-text password insertion in (Alt)DefaultPassword field in the registry
          location - HKLM/Software/Microsoft/Windows NT/WinLogon. This is readable
          by all users.
        
		"""

		path = 'windows/gather/credentials/windows_autologin'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_bulletproof_ftp(object):
		"""
		
          This module extracts information from BulletProof FTP Bookmarks files and store
        retrieved credentials in the database.
      
		"""

		path = 'windows/gather/credentials/bulletproof_ftp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_heidisql(object):
		"""
		
        This module extracts saved passwords from the HeidiSQL client. These
      passwords are stored in the registry. They are encrypted with a custom algorithm.
      This module extracts and decrypts these passwords.
      
		"""

		path = 'windows/gather/credentials/heidisql'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_mdaemon_cred_collector(object):
		"""
		
          Finds and cracks the stored passwords of MDaemon Email Server.
        
		"""

		path = 'windows/gather/credentials/mdaemon_cred_collector'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			RPATH = 'RPATH'

	class windows_gather_credentials_avira_password(object):
		"""
		
          This module extracts the weakly hashed password
          which is used to protect a Avira Antivirus (<= 15.0.17.273) installation.
        
		"""

		path = 'windows/gather/credentials/avira_password'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_razorsql(object):
		"""
		
          This module stores username, password, type, host, port, database (and name)
        collected from profiles.txt of RazorSQL.
      
		"""

		path = 'windows/gather/credentials/razorsql'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_mremote(object):
		"""
		
            This module extracts saved passwords from mRemote. mRemote stores
            connections for RDP, VNC, SSH, Telnet, rlogin and other protocols. It saves
            the passwords in an encrypted format. The module will extract the connection
            info and decrypt the saved passwords.
        
		"""

		path = 'windows/gather/credentials/mremote'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_ftpx(object):
		"""
		
        This module finds saved login credentials for the FTP Explorer (FTPx)
        FTP client for Windows.
      
		"""

		path = 'windows/gather/credentials/ftpx'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_wsftp_client(object):
		"""
		
          This module extracts weakly encrypted saved FTP Passwords
          from WS_FTP. It finds saved FTP connections in the ws_ftp.ini file.
        
		"""

		path = 'windows/gather/credentials/wsftp_client'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_steam(object):
		"""
		 This module will collect Steam session information from an
        account set to autologin. 
		"""

		path = 'windows/gather/credentials/steam'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_credentials_winscp(object):
		"""
		
        This module extracts weakly encrypted saved passwords from
        WinSCP. It searches for saved sessions in the Windows Registry
        and the WinSCP.ini file. It cannot decrypt passwords if a master
        password is used.
        
		"""

		path = 'windows/gather/credentials/winscp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_shares(object):
		"""
		 This module will enumerate configured and recently used file shares
		"""

		path = 'windows/gather/enum_shares'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_CURRENT = 'CURRENT'
			required_RECENT = 'RECENT'
			required_ENTERED = 'ENTERED'

	class windows_gather_tcpnetstat(object):
		"""
		 This Module lists current TCP sessions
		"""

		path = 'windows/gather/tcpnetstat'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_checkvm(object):
		"""
		
        This module attempts to determine whether the system is running
        inside of a virtual environment and if so, which one. This
        module supports detectoin of Hyper-V, VMWare, Virtual PC,
        VirtualBox, Xen, and QEMU.
      
		"""

		path = 'windows/gather/checkvm'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_ie(object):
		"""
		
        This module will collect history, cookies, and credentials (from either HTTP
        auth passwords, or saved form passwords found in auto-complete) in
        Internet Explorer. The ability to gather credentials is only supported
        for versions of IE >=7, while history and cookies can be extracted for all
        versions.
      
		"""

		path = 'windows/gather/enum_ie'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_ad_to_sqlite(object):
		"""
		
        This module will gather a list of AD groups, identify the users (taking into account recursion)
        and write this to a SQLite database for offline analysis and query using normal SQL syntax.
      
		"""

		path = 'windows/gather/ad_to_sqlite'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			GROUP_FILTER = 'GROUP_FILTER'
			required_SHOW_USERGROUPS = 'SHOW_USERGROUPS'
			required_SHOW_COMPUTERS = 'SHOW_COMPUTERS'
			required_THREADS = 'THREADS'

	class windows_gather_enum_domain(object):
		"""
		
        This module identifies the primary domain via the registry. The registry value used is:
        HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Group Policy/History/DCName.
        
		"""

		path = 'windows/gather/enum_domain'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_dumplinks(object):
		"""
		
          The dumplinks module is a modified port of Harlan Carvey's lslnk.pl Perl script.
          This module will parse .lnk files from a user's Recent Documents folder
          and Microsoft Office's Recent Documents folder, if present.
          Windows creates these link files automatically for many common file types.
          The .lnk files contain time stamps, file locations, including share
          names, volume serial numbers, and more. 
		"""

		path = 'windows/gather/dumplinks'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_artifacts(object):
		"""
		
        This module will check the file system and registry for particular artifacts. The
        list of artifacts is read from data/post/enum_artifacts_list.txt or a user specified file. Any
        matches are written to the loot. 
		"""

		path = 'windows/gather/enum_artifacts'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_ARTIFACTS = 'ARTIFACTS'

	class windows_gather_enum_services(object):
		"""
		
        This module will query the system for services and display name and
        configuration info for each returned service. It allows you to
        optionally search the credentials, path, or start type for a string
        and only return the results that match. These query operations are
        cumulative and if no query strings are specified, it just returns all
        services.  NOTE: If the script hangs, windows firewall is most likely
        on and you did not migrate to a safe process (explorer.exe for
        example).
        
		"""

		path = 'windows/gather/enum_services'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			CRED = 'CRED'
			PATH = 'PATH'
			required_TYPE = 'TYPE'

	class windows_gather_word_unc_injector(object):
		"""
		
          This module modifies a remote .docx file that will, upon opening, submit
        stored netNTLM credentials to a remote host. Verified to work with Microsoft
        Word 2003, 2007, 2010, and 2013. In order to get the hashes the
        auxiliary/server/capture/smb module can be used.
      
		"""

		path = 'windows/gather/word_unc_injector'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_SMBHOST = 'SMBHOST'
			required_FILE = 'FILE'
			required_BACKUP = 'BACKUP'

	class windows_gather_enum_putty_saved_sessions(object):
		"""
		
                        This module will identify whether Pageant (PuTTY Agent) is running and obtain saved session
                        information from the registry. PuTTY is very configurable; some users may have configured
                        saved sessions which could include a username, private key file to use when authenticating,
                        host name etc.  If a private key is configured, an attempt will be made to download and store
                        it in loot. It will also record the SSH host keys which have been stored. These will be connections that
                        the user has previously after accepting the host SSH fingerprint and therefore are of particular
                        interest if they are within scope of a penetration test.
                       
		"""

		path = 'windows/gather/enum_putty_saved_sessions'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_bitlocker_fvek(object):
		"""
		
        This module enumerates ways to decrypt bitlocker volume and if a recovery key is stored locally
        or can be generated, dump the Bitlocker master key (FVEK)
      
		"""

		path = 'windows/gather/bitlocker_fvek'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DRIVE_LETTER = 'DRIVE_LETTER'
			RECOVERY_KEY = 'RECOVERY_KEY'

	class windows_gather_resolve_sid(object):
		"""
		 This module prints information about a given SID from the perspective of this session 
		"""

		path = 'windows/gather/resolve_sid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_SID = 'SID'
			SYSTEM_NAME = 'SYSTEM_NAME'

	class windows_gather_enum_domain_group_users(object):
		"""
		 This module extracts user accounts from specified group
        and stores the results in the loot. It will also verify if session
        account is in the group. Data is stored in loot in a format that
        is compatible with the token_hunter plugin. This module should be
        run over as session with domain credentials.
		"""

		path = 'windows/gather/enum_domain_group_users'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_GROUP = 'GROUP'

	class windows_gather_smart_hashdump(object):
		"""
		
            This will dump local accounts from the SAM Database. If the target
          host is a Domain Controller, it will dump the Domain Account Database using the proper
          technique depending on privilege level, OS and role of the host.
        
		"""

		path = 'windows/gather/smart_hashdump'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			GETSYSTEM = 'GETSYSTEM'

	class windows_gather_enum_domains(object):
		"""
		
        This module enumerates currently the domains a host can see and the domain
        controllers for that domain.
      
		"""

		path = 'windows/gather/enum_domains'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_wmic_command(object):
		"""
		 This module will execute a given WMIC command options or read
        WMIC commands options from a resource file and execute the commands in the
        specified Meterpreter session.
		"""

		path = 'windows/gather/wmic_command'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SMBUser = 'SMBUser'
			SMBPass = 'SMBPass'
			SMBDomain = 'SMBDomain'
			required_RHOST = 'RHOST'
			required_TIMEOUT = 'TIMEOUT'
			RESOURCE = 'RESOURCE'
			COMMAND = 'COMMAND'

	class windows_gather_enum_dirperms(object):
		"""
		
        This module enumerates directories and lists the permissions set
        on found directories. Please note: if the PATH option isn't specified,
        then the module will start enumerate whatever is in the target machine's
        %PATH% variable.
      
		"""

		path = 'windows/gather/enum_dirperms'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			PATH = 'PATH'
			FILTER = 'FILTER'
			required_DEPTH = 'DEPTH'

	class windows_gather_enum_domain_users(object):
		"""
		
          This module will enumerate computers included in the primary Domain and attempt
          to list all locations the targeted user has sessions on. If a the HOST option is specified
          the module will target only that host. If the HOST is specified and USER is set to nil, all users
          logged into that host will be returned.'
        
		"""

		path = 'windows/gather/enum_domain_users'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			USER = 'USER'
			HOST = 'HOST'

	class windows_gather_enum_ad_users(object):
		"""
		
        This module will enumerate user accounts in the default Active Domain (AD) directory and stores
      them in the database. If GROUP_MEMBER is set to the DN of a group, this will list the members of
      that group by performing a recursive/nested search (i.e. it will list users who are members of
      groups that are members of groups that are members of groups (etc) which eventually include the
      target group DN.
      
		"""

		path = 'windows/gather/enum_ad_users'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			DOMAIN = 'DOMAIN'
			required_MAX_SEARCH = 'MAX_SEARCH'
			required_STORE_LOOT = 'STORE_LOOT'
			required_EXCLUDE_LOCKED = 'EXCLUDE_LOCKED'
			required_EXCLUDE_DISABLED = 'EXCLUDE_DISABLED'
			ADDITIONAL_FIELDS = 'ADDITIONAL_FIELDS'
			FILTER = 'FILTER'
			GROUP_MEMBER = 'GROUP_MEMBER'
			required_UAC = 'UAC'

	class windows_gather_enum_trusted_locations(object):
		"""
		 This module will enumerate the Microsoft Office trusted locations on the target host. 
		"""

		path = 'windows/gather/enum_trusted_locations'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_files(object):
		"""
		
        This module downloads files recursively based on the FILE_GLOBS option.
      
		"""

		path = 'windows/gather/enum_files'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			SEARCH_FROM = 'SEARCH_FROM'
			required_FILE_GLOBS = 'FILE_GLOBS'

	class windows_gather_enum_muicache(object):
		"""
		
        This module gathers information about the files and file paths that logged on users have
        executed on the system. It also will check if the file still exists on the system. This
        information is gathered by using information stored under the MUICache registry key. If
        the user is logged in when the module is executed it will collect the MUICache entries
        by accessing the registry directly. If the user is not logged in the module will download
        users registry hive NTUSER.DAT/UsrClass.dat from the system and the MUICache contents are
        parsed from the downloaded hive.
      
		"""

		path = 'windows/gather/enum_muicache'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_enum_tomcat(object):
		"""
		
        This module will collect information from a Windows-based Apache Tomcat. You will get
        information such as: The installation path, Tomcat version, port, web applications,
        users, passwords, roles, etc.
      
		"""

		path = 'windows/gather/enum_tomcat'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'

	class windows_gather_screen_spy(object):
		"""
		
          This module will incrementally take desktop screenshots from the host. This
        allows for screen spying which can be useful to determine if there is an active
        user on a machine, or to record the screen for later data extraction.

        Note: As of March, 2014, the VIEW_CMD option has been removed in
        favor of the Boolean VIEW_SCREENSHOTS option, which will control if (but
        not how) the collected screenshots will be viewed from the Metasploit
        interface.
        
		"""

		path = 'windows/gather/screen_spy'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_DELAY = 'DELAY'
			required_COUNT = 'COUNT'
			VIEW_SCREENSHOTS = 'VIEW_SCREENSHOTS'
			required_RECORD = 'RECORD'

	class windows_gather_file_from_raw_ntfs(object):
		"""
		
        This module gathers a file using the raw NTFS device, bypassing some Windows restrictions
        such as open file with write lock. Because it avoids the usual file locking issues, it can
        be used to retrieve files such as NTDS.dit.
      
		"""

		path = 'windows/gather/file_from_raw_ntfs'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_FILE_PATH = 'FILE_PATH'

	class windows_gather_bitcoin_jacker(object):
		"""
		
        This module downloads any Bitcoin wallet files from the target
        system. It currently supports both the classic Satoshi wallet and the
        more recent Armory wallets. Note that Satoshi wallets tend to be
        unencrypted by default, while Armory wallets tend to be encrypted by default.
      
		"""

		path = 'windows/gather/bitcoin_jacker'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			KILL_PROCESSES = 'KILL_PROCESSES'

	class windows_gather_local_admin_search_enum(object):
		"""
		
        This module will identify systems in a given range that the
        supplied domain user (should migrate into a user pid) has administrative
        access to by using the Windows API OpenSCManagerA to establishing a handle
        to the remote host. Additionally it can enumerate logged in users and group
        membership via Windows API NetWkstaUserEnum and NetUserGetGroups.
      
		"""

		path = 'windows/gather/local_admin_search_enum'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_RHOSTS = 'RHOSTS'
			required_THREADS = 'THREADS'
			required_ShowProgress = 'ShowProgress'
			required_ShowProgressPercent = 'ShowProgressPercent'
			required_ENUM_USERS = 'ENUM_USERS'
			ENUM_GROUPS = 'ENUM_GROUPS'
			DOMAIN = 'DOMAIN'
			DOMAIN_CONTROLLER = 'DOMAIN_CONTROLLER'

	class windows_gather_reverse_lookup(object):
		"""
		
        This module uses Railgun, calling the gethostbyaddr function to resolve a hostname
        to an IP.
      
		"""

		path = 'windows/gather/reverse_lookup'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_SESSION = 'SESSION'
			required_RHOSTS = 'RHOSTS'
