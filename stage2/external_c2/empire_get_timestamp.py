from EmpireAPIWrapper import empireAPI
from empire_settings import *


def run(API, agent_name, time_out_sec = 180):
    """
    Returns timestamp in the format of: 
    \nTuesday, September 12, 2017 11:29:43 AM 
    \n:param agent_name: name of Empire agent
    \n:param time_out_sec: time out in seconds
    \n:return type: string
    """
    params = {'AGENT': agent_name, 'command': '(Get-Date -Format F).ToString()'}
    return API.agent_run_shell_cmd_with_result(agent_name, params)    
    
    
if __name__ == '__main__':
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    output = run(API,'LHEU6NV3')    
    print(output)
