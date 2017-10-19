""" 
Wait for an Empire agent with a given hostname or IP address
"""
from time import sleep
from EmpireAPIWrapper import empireAPI
from c2_settings import EMPIRE_PWD, EMPIRE_SERVER, EMPIRE_USER

def run(API, host_name, need_privilege=False, time_out_sec = 180):
    """
    Returns agent info in a dictionary when found, else raise exception
    \n:param API: EmpireAPIWrapper.empireAPI object
    \n:param host_name: target's host name
    \n:param need_privilege: set to true if need privileged agent
    \n:param time_out_sec: time out in seconds
    \n:return type: dict
    """
    time_out = time_out_sec
    agent_name = ""
    step = 2
    while time_out > 0:
        agent_name = API.agent_get_name(host_name, need_privilege)        
        if len(agent_name) > 0:
            return API.agent_info(agent_name)['agents'][0]
        time_out -= step
        sleep(step)
    raise ValueError('Wait for agent timeout')


# for unit testing of each technique
if __name__ == '__main__':
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    print(run(API, 'pec-WIN10PRO64')) # agent without high-integrity
    print(run(API, 'pec-WIN10PRO64', True)) # agent with high-integrity
    print(run(API, 'BLAH_BLAH')) # no such host
    
