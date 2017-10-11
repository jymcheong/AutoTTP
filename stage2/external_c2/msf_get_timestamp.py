""" 
Get timestamp of target from Metasploit session (Shell & Meterpreter)
Note that timestamp string is a different for the 2 types of session
"""
from time import sleep
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient

def run(client, session_id):
    """
    Given an IP, waits for session, else Raise ValueError if timeout
    \n:param client: MsfRpcClient object
    \n:param ip_address: target's IP address
    \n:return type: string (timestamp) else None
    """
    shell = client.sessions.session(session_id)
    if('Shell' in str(type(shell))):
        shell.write('echo %date% %time%\n') # the newline is important! 
    else:
        shell.write('localtime\n')
    sleep(2)
    r = shell.read()
    if('echo' in r):
        r = r.split("\n")[1]
    return r 


# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    print(run(client, 3))