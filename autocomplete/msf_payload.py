""" This is generated autocomplete helper class for MSF """
class payload(object):
	class windows_adduser(object):
		"""
		
        Create a new user and add them to local administration group.

        Note: The specified password is checked for common complexity
        requirements to prevent the target machine rejecting the user
        for failing to meet policy requirements.

        Complexity check: 8-14 chars (1 UPPER, 1 lower, 1 digit/special)
      
		"""

		path = 'windows/adduser'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_USER = 'USER'
			required_PASS = 'PASS'
			CUSTOM = 'CUSTOM'
			required_WMIC = 'WMIC'
			required_COMPLEXITY = 'COMPLEXITY'

	class windows_metsvc_bind_tcp(object):
		"""
		Stub payload for interacting with a Meterpreter Service
		"""

		path = 'windows/metsvc_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_shell_hidden_bind_tcp(object):
		"""
		Listen for a connection from certain IP and spawn a command shell.
                          The shellcode will reply with a RST packet if the connections is not
                          comming from the IP defined in AHOST. This way the port will appear
                          as "closed" helping us to hide the shellcode.
		"""

		path = 'windows/shell_hidden_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AHOST = 'AHOST'

	class windows_x64_meterpreter_reverse_http(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/x64/meterpreter_reverse_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_x64_exec(object):
		"""
		Execute an arbitrary command (Windows x64)
		"""

		path = 'windows/x64/exec'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_CMD = 'CMD'

	class windows_x64_meterpreter_reverse_https(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/x64/meterpreter_reverse_https'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_x64_powershell_reverse_tcp(object):
		"""
		Listen for a connection and spawn an interactive powershell session
		"""

		path = 'windows/x64/powershell_reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			HandlerSSLCert = 'HandlerSSLCert'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			LOAD_MODULES = 'LOAD_MODULES'

	class windows_x64_loadlibrary(object):
		"""
		Load an arbitrary x64 library path
		"""

		path = 'windows/x64/loadlibrary'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_x64_powershell_bind_tcp(object):
		"""
		Listen for a connection and spawn an interactive powershell session
		"""

		path = 'windows/x64/powershell_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			LOAD_MODULES = 'LOAD_MODULES'

	class windows_x64_shell_bind_tcp(object):
		"""
		Listen for a connection and spawn a command shell (Windows x64)
		"""

		path = 'windows/x64/shell_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_shell_reverse_tcp(object):
		"""
		Connect back to attacker and spawn a command shell (Windows x64)
		"""

		path = 'windows/x64/shell_reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_meterpreter_bind_tcp(object):
		"""
		Connect to victim and spawn a Meterpreter shell
		"""

		path = 'windows/x64/meterpreter_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_x64_meterpreter_reverse_ipv6_tcp(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/x64/meterpreter_reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'
			SCOPEID = 'SCOPEID'

	class windows_x64_meterpreter_reverse_tcp(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/x64/meterpreter_reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_meterpreter_reverse_http(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/meterpreter_reverse_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_exec(object):
		"""
		Execute an arbitrary command
		"""

		path = 'windows/exec'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_CMD = 'CMD'

	class windows_meterpreter_reverse_https(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/meterpreter_reverse_https'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_powershell_reverse_tcp(object):
		"""
		Listen for a connection and spawn an interactive powershell session
		"""

		path = 'windows/powershell_reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			HandlerSSLCert = 'HandlerSSLCert'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			LOAD_MODULES = 'LOAD_MODULES'

	class windows_loadlibrary(object):
		"""
		Load an arbitrary library path
		"""

		path = 'windows/loadlibrary'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_powershell_bind_tcp(object):
		"""
		Listen for a connection and spawn an interactive powershell session
		"""

		path = 'windows/powershell_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			LOAD_MODULES = 'LOAD_MODULES'

	class windows_dns_txt_query_exec(object):
		"""
		Performs a TXT query against a series of DNS record(s) and executes the returned payload
		"""

		path = 'windows/dns_txt_query_exec'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_DNSZONE = 'DNSZONE'

	class windows_shell_bind_tcp_xpfw(object):
		"""
		Disable the Windows ICF, then listen for a connection and spawn a command shell
		"""

		path = 'windows/shell_bind_tcp_xpfw'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_shell_bind_tcp(object):
		"""
		Listen for a connection and spawn a command shell
		"""

		path = 'windows/shell_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_shell_reverse_tcp(object):
		"""
		Connect back to attacker and spawn a command shell
		"""

		path = 'windows/shell_reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_messagebox(object):
		"""
		Spawns a dialog via MessageBox using a customizable title, text & icon
		"""

		path = 'windows/messagebox'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_TITLE = 'TITLE'
			required_TEXT = 'TEXT'
			required_ICON = 'ICON'

	class windows_download_exec(object):
		"""
		Download an EXE from an HTTP(S)/FTP URL and execute it
		"""

		path = 'windows/download_exec'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_URL = 'URL'
			required_EXE = 'EXE'

	class windows_speak_pwned(object):
		"""
		Causes the target to say "You Got Pwned" via the Windows Speech API
		"""

		path = 'windows/speak_pwned'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'

	class windows_meterpreter_bind_tcp(object):
		"""
		Connect to victim and spawn a Meterpreter shell
		"""

		path = 'windows/meterpreter_bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_meterpreter_reverse_ipv6_tcp(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/meterpreter_reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'
			SCOPEID = 'SCOPEID'

	class windows_metsvc_reverse_tcp(object):
		"""
		Stub payload for interacting with a Meterpreter Service
		"""

		path = 'windows/metsvc_reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_meterpreter_reverse_tcp(object):
		"""
		Connect back to attacker and spawn a Meterpreter shell
		"""

		path = 'windows/meterpreter_reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
			EXTENSIONS = 'EXTENSIONS'
			EXTINIT = 'EXTINIT'

	class windows_format_all_drives(object):
		"""
		
        This payload formats all mounted disks in Windows (aka ShellcodeOfDeath).

        After formatting, this payload sets the volume label to the string specified in
        the VOLUMELABEL option. If the code is unable to access a drive for any reason,
        it skips the drive and proceeds to the next volume.
      
		"""

		path = 'windows/format_all_drives'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			VOLUMELABEL = 'VOLUMELABEL'

	class windows_dllinject_reverse_ipv6_tcp(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker over IPv6
		"""

		path = 'windows/dllinject/reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			SCOPEID = 'SCOPEID'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_ipv6_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker over IPv6
		"""

		path = 'windows/patchupmeterpreter/reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			SCOPEID = 'SCOPEID'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_ipv6_tcp(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker over IPv6
		"""

		path = 'windows/upexec/reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			SCOPEID = 'SCOPEID'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_ipv6_tcp(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker over IPv6
		"""

		path = 'windows/shell/reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			SCOPEID = 'SCOPEID'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_ipv6_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker over IPv6
		"""

		path = 'windows/vncinject/reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			SCOPEID = 'SCOPEID'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_ipv6_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker over IPv6
		"""

		path = 'windows/meterpreter/reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			SCOPEID = 'SCOPEID'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_ipv6_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker over IPv6
		"""

		path = 'windows/patchupdllinject/reverse_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			SCOPEID = 'SCOPEID'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_bind_ipv6_tcp_uuid(object):
		"""
		Inject a DLL via a reflective loader. Listen for an IPv6 connection with UUID Support (Windows x86)
		"""

		path = 'windows/dllinject/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_ipv6_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for an IPv6 connection with UUID Support (Windows x86)
		"""

		path = 'windows/patchupmeterpreter/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_ipv6_tcp_uuid(object):
		"""
		Uploads an executable and runs it (staged). Listen for an IPv6 connection with UUID Support (Windows x86)
		"""

		path = 'windows/upexec/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_ipv6_tcp_uuid(object):
		"""
		Spawn a piped command shell (staged). Listen for an IPv6 connection with UUID Support (Windows x86)
		"""

		path = 'windows/shell/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_ipv6_tcp_uuid(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for an IPv6 connection with UUID Support (Windows x86)
		"""

		path = 'windows/vncinject/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_ipv6_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for an IPv6 connection with UUID Support (Windows x86)
		"""

		path = 'windows/meterpreter/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_ipv6_tcp_uuid(object):
		"""
		Inject a custom DLL into the exploited process. Listen for an IPv6 connection with UUID Support (Windows x86)
		"""

		path = 'windows/patchupdllinject/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_tcp_dns(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker
		"""

		path = 'windows/dllinject/reverse_tcp_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_tcp_dns(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker
		"""

		path = 'windows/patchupmeterpreter/reverse_tcp_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_tcp_dns(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker
		"""

		path = 'windows/upexec/reverse_tcp_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_tcp_dns(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker
		"""

		path = 'windows/shell/reverse_tcp_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_tcp_dns(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker
		"""

		path = 'windows/vncinject/reverse_tcp_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_tcp_dns(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker
		"""

		path = 'windows/meterpreter/reverse_tcp_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_tcp_dns(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker
		"""

		path = 'windows/patchupdllinject/reverse_tcp_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_x64_shell_bind_ipv6_tcp_uuid(object):
		"""
		Spawn a piped command shell (Windows x64) (staged). Listen for an IPv6 connection with UUID Support (Windows x64)
		"""

		path = 'windows/x64/shell/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_vncinject_bind_ipv6_tcp_uuid(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Listen for an IPv6 connection with UUID Support (Windows x64)
		"""

		path = 'windows/x64/vncinject/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_bind_ipv6_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Listen for an IPv6 connection with UUID Support (Windows x64)
		"""

		path = 'windows/x64/meterpreter/bind_ipv6_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_shell_bind_tcp_uuid(object):
		"""
		Spawn a piped command shell (Windows x64) (staged). Listen for a connection with UUID Support (Windows x64)
		"""

		path = 'windows/x64/shell/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_vncinject_bind_tcp_uuid(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Listen for a connection with UUID Support (Windows x64)
		"""

		path = 'windows/x64/vncinject/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_bind_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Listen for a connection with UUID Support (Windows x64)
		"""

		path = 'windows/x64/meterpreter/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_shell_bind_ipv6_tcp(object):
		"""
		Spawn a piped command shell (Windows x64) (staged). Listen for an IPv6 connection (Windows x64)
		"""

		path = 'windows/x64/shell/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_vncinject_bind_ipv6_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Listen for an IPv6 connection (Windows x64)
		"""

		path = 'windows/x64/vncinject/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_bind_ipv6_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Listen for an IPv6 connection (Windows x64)
		"""

		path = 'windows/x64/meterpreter/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_vncinject_reverse_winhttp(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Tunnel communication over HTTP (Windows x64 winhttp)
		"""

		path = 'windows/x64/vncinject/reverse_winhttp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_reverse_winhttp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Tunnel communication over HTTP (Windows x64 winhttp)
		"""

		path = 'windows/x64/meterpreter/reverse_winhttp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_vncinject_reverse_https(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Tunnel communication over HTTP (Windows x64 wininet)
		"""

		path = 'windows/x64/vncinject/reverse_https'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_reverse_https(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Tunnel communication over HTTP (Windows x64 wininet)
		"""

		path = 'windows/x64/meterpreter/reverse_https'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_vncinject_reverse_winhttps(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Tunnel communication over HTTPS (Windows x64 winhttp)
		"""

		path = 'windows/x64/vncinject/reverse_winhttps'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_reverse_winhttps(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Tunnel communication over HTTPS (Windows x64 winhttp)
		"""

		path = 'windows/x64/meterpreter/reverse_winhttps'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_shell_reverse_tcp_uuid(object):
		"""
		Spawn a piped command shell (Windows x64) (staged). Connect back to the attacker with UUID Support (Windows x64)
		"""

		path = 'windows/x64/shell/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_vncinject_reverse_tcp_uuid(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Connect back to the attacker with UUID Support (Windows x64)
		"""

		path = 'windows/x64/vncinject/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_reverse_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Connect back to the attacker with UUID Support (Windows x64)
		"""

		path = 'windows/x64/meterpreter/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_shell_bind_tcp(object):
		"""
		Spawn a piped command shell (Windows x64) (staged). Listen for a connection (Windows x64)
		"""

		path = 'windows/x64/shell/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_vncinject_bind_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Listen for a connection (Windows x64)
		"""

		path = 'windows/x64/vncinject/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_bind_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Listen for a connection (Windows x64)
		"""

		path = 'windows/x64/meterpreter/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_vncinject_reverse_http(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Tunnel communication over HTTP (Windows x64 wininet)
		"""

		path = 'windows/x64/vncinject/reverse_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_reverse_http(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Tunnel communication over HTTP (Windows x64 wininet)
		"""

		path = 'windows/x64/meterpreter/reverse_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_x64_shell_reverse_tcp(object):
		"""
		Spawn a piped command shell (Windows x64) (staged). Connect back to the attacker (Windows x64)
		"""

		path = 'windows/x64/shell/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_x64_vncinject_reverse_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (Windows x64) (staged). Connect back to the attacker (Windows x64)
		"""

		path = 'windows/x64/vncinject/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_x64_meterpreter_reverse_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64). Connect back to the attacker (Windows x64)
		"""

		path = 'windows/x64/meterpreter/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_dllinject_reverse_http_proxy_pstore(object):
		"""
		Inject a DLL via a reflective loader. Tunnel communication over HTTP
		"""

		path = 'windows/dllinject/reverse_http_proxy_pstore'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_vncinject_reverse_http_proxy_pstore(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Tunnel communication over HTTP
		"""

		path = 'windows/vncinject/reverse_http_proxy_pstore'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_http_proxy_pstore(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel communication over HTTP
		"""

		path = 'windows/meterpreter/reverse_http_proxy_pstore'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_dllinject_reverse_ord_tcp(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker
		"""

		path = 'windows/dllinject/reverse_ord_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_ord_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker
		"""

		path = 'windows/patchupmeterpreter/reverse_ord_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_ord_tcp(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker
		"""

		path = 'windows/upexec/reverse_ord_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_ord_tcp(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker
		"""

		path = 'windows/shell/reverse_ord_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_ord_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker
		"""

		path = 'windows/vncinject/reverse_ord_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_ord_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker
		"""

		path = 'windows/meterpreter/reverse_ord_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_ord_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker
		"""

		path = 'windows/patchupdllinject/reverse_ord_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_tcp_allports(object):
		"""
		Inject a DLL via a reflective loader. Try to connect back to the attacker, on all possible ports (1-65535, slowly)
		"""

		path = 'windows/dllinject/reverse_tcp_allports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_tcp_allports(object):
		"""
		Inject the meterpreter server DLL (staged). Try to connect back to the attacker, on all possible ports (1-65535, slowly)
		"""

		path = 'windows/patchupmeterpreter/reverse_tcp_allports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_tcp_allports(object):
		"""
		Uploads an executable and runs it (staged). Try to connect back to the attacker, on all possible ports (1-65535, slowly)
		"""

		path = 'windows/upexec/reverse_tcp_allports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_tcp_allports(object):
		"""
		Spawn a piped command shell (staged). Try to connect back to the attacker, on all possible ports (1-65535, slowly)
		"""

		path = 'windows/shell/reverse_tcp_allports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_tcp_allports(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Try to connect back to the attacker, on all possible ports (1-65535, slowly)
		"""

		path = 'windows/vncinject/reverse_tcp_allports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_tcp_allports(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Try to connect back to the attacker, on all possible ports (1-65535, slowly)
		"""

		path = 'windows/meterpreter/reverse_tcp_allports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_tcp_allports(object):
		"""
		Inject a custom DLL into the exploited process. Try to connect back to the attacker, on all possible ports (1-65535, slowly)
		"""

		path = 'windows/patchupdllinject/reverse_tcp_allports'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_tcp_rc4(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker
		"""

		path = 'windows/dllinject/reverse_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_tcp_rc4(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker
		"""

		path = 'windows/patchupmeterpreter/reverse_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_tcp_rc4(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker
		"""

		path = 'windows/upexec/reverse_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_tcp_rc4(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker
		"""

		path = 'windows/shell/reverse_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_tcp_rc4(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker
		"""

		path = 'windows/vncinject/reverse_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_tcp_rc4(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker
		"""

		path = 'windows/meterpreter/reverse_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_tcp_rc4(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker
		"""

		path = 'windows/patchupdllinject/reverse_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_tcp_rc4_dns(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker
		"""

		path = 'windows/dllinject/reverse_tcp_rc4_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_tcp_rc4_dns(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker
		"""

		path = 'windows/patchupmeterpreter/reverse_tcp_rc4_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_tcp_rc4_dns(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker
		"""

		path = 'windows/upexec/reverse_tcp_rc4_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_tcp_rc4_dns(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker
		"""

		path = 'windows/shell/reverse_tcp_rc4_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_tcp_rc4_dns(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker
		"""

		path = 'windows/vncinject/reverse_tcp_rc4_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_tcp_rc4_dns(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker
		"""

		path = 'windows/meterpreter/reverse_tcp_rc4_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_tcp_rc4_dns(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker
		"""

		path = 'windows/patchupdllinject/reverse_tcp_rc4_dns'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_bind_tcp_uuid(object):
		"""
		Inject a DLL via a reflective loader. Listen for a connection with UUID Support (Windows x86)
		"""

		path = 'windows/dllinject/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for a connection with UUID Support (Windows x86)
		"""

		path = 'windows/patchupmeterpreter/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_tcp_uuid(object):
		"""
		Uploads an executable and runs it (staged). Listen for a connection with UUID Support (Windows x86)
		"""

		path = 'windows/upexec/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_tcp_uuid(object):
		"""
		Spawn a piped command shell (staged). Listen for a connection with UUID Support (Windows x86)
		"""

		path = 'windows/shell/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_tcp_uuid(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for a connection with UUID Support (Windows x86)
		"""

		path = 'windows/vncinject/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for a connection with UUID Support (Windows x86)
		"""

		path = 'windows/meterpreter/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_tcp_uuid(object):
		"""
		Inject a custom DLL into the exploited process. Listen for a connection with UUID Support (Windows x86)
		"""

		path = 'windows/patchupdllinject/bind_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_bind_ipv6_tcp(object):
		"""
		Inject a DLL via a reflective loader. Listen for an IPv6 connection (Windows x86)
		"""

		path = 'windows/dllinject/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_ipv6_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for an IPv6 connection (Windows x86)
		"""

		path = 'windows/patchupmeterpreter/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_ipv6_tcp(object):
		"""
		Uploads an executable and runs it (staged). Listen for an IPv6 connection (Windows x86)
		"""

		path = 'windows/upexec/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_ipv6_tcp(object):
		"""
		Spawn a piped command shell (staged). Listen for an IPv6 connection (Windows x86)
		"""

		path = 'windows/shell/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_ipv6_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for an IPv6 connection (Windows x86)
		"""

		path = 'windows/vncinject/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_ipv6_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for an IPv6 connection (Windows x86)
		"""

		path = 'windows/meterpreter/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_ipv6_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Listen for an IPv6 connection (Windows x86)
		"""

		path = 'windows/patchupdllinject/bind_ipv6_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_winhttp(object):
		"""
		Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows winhttp)
		"""

		path = 'windows/dllinject/reverse_winhttp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			required_DLL = 'DLL'

	class windows_vncinject_reverse_winhttp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Tunnel communication over HTTP (Windows winhttp)
		"""

		path = 'windows/vncinject/reverse_winhttp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_winhttp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel communication over HTTP (Windows winhttp)
		"""

		path = 'windows/meterpreter/reverse_winhttp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_dllinject_find_tag(object):
		"""
		Inject a DLL via a reflective loader. Use an established connection
		"""

		path = 'windows/dllinject/find_tag'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_TAG = 'TAG'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_find_tag(object):
		"""
		Inject the meterpreter server DLL (staged). Use an established connection
		"""

		path = 'windows/patchupmeterpreter/find_tag'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_TAG = 'TAG'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_find_tag(object):
		"""
		Uploads an executable and runs it (staged). Use an established connection
		"""

		path = 'windows/upexec/find_tag'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_TAG = 'TAG'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_find_tag(object):
		"""
		Spawn a piped command shell (staged). Use an established connection
		"""

		path = 'windows/shell/find_tag'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_TAG = 'TAG'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_find_tag(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Use an established connection
		"""

		path = 'windows/vncinject/find_tag'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_TAG = 'TAG'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_find_tag(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Use an established connection
		"""

		path = 'windows/meterpreter/find_tag'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_TAG = 'TAG'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_find_tag(object):
		"""
		Inject a custom DLL into the exploited process. Use an established connection
		"""

		path = 'windows/patchupdllinject/find_tag'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_TAG = 'TAG'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_bind_tcp_rc4(object):
		"""
		Inject a DLL via a reflective loader. Listen for a connection
		"""

		path = 'windows/dllinject/bind_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_tcp_rc4(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for a connection
		"""

		path = 'windows/patchupmeterpreter/bind_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_tcp_rc4(object):
		"""
		Uploads an executable and runs it (staged). Listen for a connection
		"""

		path = 'windows/upexec/bind_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_tcp_rc4(object):
		"""
		Spawn a piped command shell (staged). Listen for a connection
		"""

		path = 'windows/shell/bind_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_tcp_rc4(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for a connection
		"""

		path = 'windows/vncinject/bind_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_tcp_rc4(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for a connection
		"""

		path = 'windows/meterpreter/bind_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_tcp_rc4(object):
		"""
		Inject a custom DLL into the exploited process. Listen for a connection
		"""

		path = 'windows/patchupdllinject/bind_tcp_rc4'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_RC4PASSWORD = 'RC4PASSWORD'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_meterpreter_reverse_https(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel communication over HTTPS (Windows wininet)
		"""

		path = 'windows/meterpreter/reverse_https'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_meterpreter_reverse_winhttps(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel communication over HTTPS (Windows winhttp)
		"""

		path = 'windows/meterpreter/reverse_winhttps'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			HandlerSSLCert = 'HandlerSSLCert'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			PayloadProxyIE = 'PayloadProxyIE'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			StagerVerifySSLCert = 'StagerVerifySSLCert'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_dllinject_reverse_tcp_uuid(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker with UUID Support
		"""

		path = 'windows/dllinject/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker with UUID Support
		"""

		path = 'windows/patchupmeterpreter/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_tcp_uuid(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker with UUID Support
		"""

		path = 'windows/upexec/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_tcp_uuid(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker with UUID Support
		"""

		path = 'windows/shell/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_tcp_uuid(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker with UUID Support
		"""

		path = 'windows/vncinject/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_tcp_uuid(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker with UUID Support
		"""

		path = 'windows/meterpreter/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_tcp_uuid(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker with UUID Support
		"""

		path = 'windows/patchupdllinject/reverse_tcp_uuid'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_nonx_tcp(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker (No NX)
		"""

		path = 'windows/dllinject/reverse_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_nonx_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker (No NX)
		"""

		path = 'windows/patchupmeterpreter/reverse_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_nonx_tcp(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker (No NX)
		"""

		path = 'windows/upexec/reverse_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_nonx_tcp(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker (No NX)
		"""

		path = 'windows/shell/reverse_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_nonx_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker (No NX)
		"""

		path = 'windows/vncinject/reverse_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_nonx_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker (No NX)
		"""

		path = 'windows/meterpreter/reverse_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_nonx_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker (No NX)
		"""

		path = 'windows/patchupdllinject/reverse_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_bind_tcp(object):
		"""
		Inject a DLL via a reflective loader. Listen for a connection (Windows x86)
		"""

		path = 'windows/dllinject/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for a connection (Windows x86)
		"""

		path = 'windows/patchupmeterpreter/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_tcp(object):
		"""
		Uploads an executable and runs it (staged). Listen for a connection (Windows x86)
		"""

		path = 'windows/upexec/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_tcp(object):
		"""
		Spawn a piped command shell (staged). Listen for a connection (Windows x86)
		"""

		path = 'windows/shell/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for a connection (Windows x86)
		"""

		path = 'windows/vncinject/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for a connection (Windows x86)
		"""

		path = 'windows/meterpreter/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Listen for a connection (Windows x86)
		"""

		path = 'windows/patchupdllinject/bind_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_bind_nonx_tcp(object):
		"""
		Inject a DLL via a reflective loader. Listen for a connection (No NX)
		"""

		path = 'windows/dllinject/bind_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_nonx_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for a connection (No NX)
		"""

		path = 'windows/patchupmeterpreter/bind_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_nonx_tcp(object):
		"""
		Uploads an executable and runs it (staged). Listen for a connection (No NX)
		"""

		path = 'windows/upexec/bind_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_nonx_tcp(object):
		"""
		Spawn a piped command shell (staged). Listen for a connection (No NX)
		"""

		path = 'windows/shell/bind_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_nonx_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for a connection (No NX)
		"""

		path = 'windows/vncinject/bind_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_nonx_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for a connection (No NX)
		"""

		path = 'windows/meterpreter/bind_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_nonx_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Listen for a connection (No NX)
		"""

		path = 'windows/patchupdllinject/bind_nonx_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_http(object):
		"""
		Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows wininet)
		"""

		path = 'windows/dllinject/reverse_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_DLL = 'DLL'

	class windows_vncinject_reverse_http(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Tunnel communication over HTTP (Windows wininet)
		"""

		path = 'windows/vncinject/reverse_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_http(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel communication over HTTP (Windows wininet)
		"""

		path = 'windows/meterpreter/reverse_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			StagerURILength = 'StagerURILength'
			StagerRetryCount = 'StagerRetryCount'
			StagerRetryWait = 'StagerRetryWait'
			PayloadProxyHost = 'PayloadProxyHost'
			PayloadProxyPort = 'PayloadProxyPort'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadProxyType = 'PayloadProxyType'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_dllinject_bind_hidden_ipknock_tcp(object):
		"""
		Inject a DLL via a reflective loader. Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode
		"""

		path = 'windows/dllinject/bind_hidden_ipknock_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_KHOST = 'KHOST'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_hidden_ipknock_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode
		"""

		path = 'windows/patchupmeterpreter/bind_hidden_ipknock_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_KHOST = 'KHOST'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_hidden_ipknock_tcp(object):
		"""
		Uploads an executable and runs it (staged). Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode
		"""

		path = 'windows/upexec/bind_hidden_ipknock_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_KHOST = 'KHOST'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_hidden_ipknock_tcp(object):
		"""
		Spawn a piped command shell (staged). Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode
		"""

		path = 'windows/shell/bind_hidden_ipknock_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_KHOST = 'KHOST'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_hidden_ipknock_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode
		"""

		path = 'windows/vncinject/bind_hidden_ipknock_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_KHOST = 'KHOST'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_hidden_ipknock_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode
		"""

		path = 'windows/meterpreter/bind_hidden_ipknock_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_KHOST = 'KHOST'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_hidden_ipknock_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode
		"""

		path = 'windows/patchupdllinject/bind_hidden_ipknock_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_KHOST = 'KHOST'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_hop_http(object):
		"""
		Inject a DLL via a reflective loader. 
        Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload
        data/hop/hop.php to the PHP server you wish to use as a hop.
      
		"""

		path = 'windows/dllinject/reverse_hop_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			required_HOPURL = 'HOPURL'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_vncinject_reverse_hop_http(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). 
        Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload
        data/hop/hop.php to the PHP server you wish to use as a hop.
      
		"""

		path = 'windows/vncinject/reverse_hop_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			required_HOPURL = 'HOPURL'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_hop_http(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). 
        Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload
        data/hop/hop.php to the PHP server you wish to use as a hop.
      
		"""

		path = 'windows/meterpreter/reverse_hop_http'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			required_HOPURL = 'HOPURL'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_dllinject_bind_hidden_tcp(object):
		"""
		Inject a DLL via a reflective loader. Listen for a connection from a hidden port and spawn a command shell to the allowed host.
		"""

		path = 'windows/dllinject/bind_hidden_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AHOST = 'AHOST'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_bind_hidden_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Listen for a connection from a hidden port and spawn a command shell to the allowed host.
		"""

		path = 'windows/patchupmeterpreter/bind_hidden_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AHOST = 'AHOST'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_bind_hidden_tcp(object):
		"""
		Uploads an executable and runs it (staged). Listen for a connection from a hidden port and spawn a command shell to the allowed host.
		"""

		path = 'windows/upexec/bind_hidden_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AHOST = 'AHOST'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_bind_hidden_tcp(object):
		"""
		Spawn a piped command shell (staged). Listen for a connection from a hidden port and spawn a command shell to the allowed host.
		"""

		path = 'windows/shell/bind_hidden_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AHOST = 'AHOST'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_bind_hidden_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Listen for a connection from a hidden port and spawn a command shell to the allowed host.
		"""

		path = 'windows/vncinject/bind_hidden_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AHOST = 'AHOST'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_bind_hidden_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Listen for a connection from a hidden port and spawn a command shell to the allowed host.
		"""

		path = 'windows/meterpreter/bind_hidden_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AHOST = 'AHOST'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_bind_hidden_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Listen for a connection from a hidden port and spawn a command shell to the allowed host.
		"""

		path = 'windows/patchupdllinject/bind_hidden_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LPORT = 'LPORT'
			RHOST = 'RHOST'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AHOST = 'AHOST'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_dllinject_reverse_tcp(object):
		"""
		Inject a DLL via a reflective loader. Connect back to the attacker
		"""

		path = 'windows/dllinject/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'

	class windows_patchupmeterpreter_reverse_tcp(object):
		"""
		Inject the meterpreter server DLL (staged). Connect back to the attacker
		"""

		path = 'windows/patchupmeterpreter/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_upexec_reverse_tcp(object):
		"""
		Uploads an executable and runs it (staged). Connect back to the attacker
		"""

		path = 'windows/upexec/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_PEXEC = 'PEXEC'

	class windows_shell_reverse_tcp(object):
		"""
		Spawn a piped command shell (staged). Connect back to the attacker
		"""

		path = 'windows/shell/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'

	class windows_vncinject_reverse_tcp(object):
		"""
		Inject a VNC Dll via a reflective loader (staged). Connect back to the attacker
		"""

		path = 'windows/vncinject/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_VNCPORT = 'VNCPORT'
			required_VNCHOST = 'VNCHOST'
			DisableCourtesyShell = 'DisableCourtesyShell'
			ViewOnly = 'ViewOnly'
			required_AUTOVNC = 'AUTOVNC'
			DisableSessionTracking = 'DisableSessionTracking'

	class windows_meterpreter_reverse_tcp(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker
		"""

		path = 'windows/meterpreter/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'

	class windows_patchupdllinject_reverse_tcp(object):
		"""
		Inject a custom DLL into the exploited process. Connect back to the attacker
		"""

		path = 'windows/patchupdllinject/reverse_tcp'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			ReverseListenerComm = 'ReverseListenerComm'
			required_ReverseConnectRetries = 'ReverseConnectRetries'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			required_ReverseListenerThreaded = 'ReverseListenerThreaded'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_DLL = 'DLL'
			LibraryName = 'LibraryName'

	class windows_meterpreter_reverse_https_proxy(object):
		"""
		Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel communication over HTTP using SSL with custom proxy support
		"""

		path = 'windows/meterpreter/reverse_https_proxy'
		class options(object):
			WORKSPACE = 'WORKSPACE'
			VERBOSE = 'VERBOSE'
			required_LHOST = 'LHOST'
			required_LPORT = 'LPORT'
			ReverseListenerBindPort = 'ReverseListenerBindPort'
			required_ReverseAllowProxy = 'ReverseAllowProxy'
			LURI = 'LURI'
			MeterpreterUserAgent = 'MeterpreterUserAgent'
			MeterpreterServerName = 'MeterpreterServerName'
			ReverseListenerBindAddress = 'ReverseListenerBindAddress'
			OverrideRequestHost = 'OverrideRequestHost'
			OverrideLHOST = 'OverrideLHOST'
			OverrideLPORT = 'OverrideLPORT'
			OverrideScheme = 'OverrideScheme'
			HttpUnknownRequestResponse = 'HttpUnknownRequestResponse'
			IgnoreUnknownPayloads = 'IgnoreUnknownPayloads'
			required_PayloadProxyHost = 'PayloadProxyHost'
			required_PayloadProxyPort = 'PayloadProxyPort'
			required_PayloadProxyType = 'PayloadProxyType'
			PayloadProxyUser = 'PayloadProxyUser'
			PayloadProxyPass = 'PayloadProxyPass'
			PayloadUUIDSeed = 'PayloadUUIDSeed'
			PayloadUUIDRaw = 'PayloadUUIDRaw'
			PayloadUUIDName = 'PayloadUUIDName'
			required_PayloadUUIDTracking = 'PayloadUUIDTracking'
			EnableStageEncoding = 'EnableStageEncoding'
			StageEncoder = 'StageEncoder'
			StageEncoderSaveRegisters = 'StageEncoderSaveRegisters'
			StageEncodingFallback = 'StageEncodingFallback'
			required_PrependMigrate = 'PrependMigrate'
			PrependMigrateProc = 'PrependMigrateProc'
			required_EXITFUNC = 'EXITFUNC'
			required_AutoLoadStdapi = 'AutoLoadStdapi'
			required_AutoVerifySession = 'AutoVerifySession'
			AutoVerifySessionTimeout = 'AutoVerifySessionTimeout'
			InitialAutoRunScript = 'InitialAutoRunScript'
			AutoRunScript = 'AutoRunScript'
			required_AutoSystemInfo = 'AutoSystemInfo'
			required_EnableUnicodeEncoding = 'EnableUnicodeEncoding'
			HandlerSSLCert = 'HandlerSSLCert'
			SessionRetryTotal = 'SessionRetryTotal'
			SessionRetryWait = 'SessionRetryWait'
			SessionExpirationTimeout = 'SessionExpirationTimeout'
			SessionCommunicationTimeout = 'SessionCommunicationTimeout'
