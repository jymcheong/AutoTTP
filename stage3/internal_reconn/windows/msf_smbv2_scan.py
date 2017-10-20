"""
Detect systems that support the SMB 2.0 protocol.
Run Autoroute before scanning, else u may get nothing.
use auxiliary/scanner/smb/smb2
set RHOSTS 192.168.181.190-200 (range)
"""
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from time import sleep

def run(client, RHOSTS, THREADS=''):
    """
    Setup autoroute for pivoting via existing Meterpreter session
    \n:param client: MsfRpcClient object
    \n:param SESSION: numeric session id
    \n:param RHOSTS: range eg. 10.10.10.1-254 
    \n:return type: list of IPs or empty list if none found
    """

    console = client.consoles.console()
    # copy from Armitage
    console.write('use auxiliary/scanner/smb/smb2')
    console.write('set RHOSTS {0}'.format(RHOSTS))    
    if(THREADS is ''):
        console.write('set THREADS 20')    
    else:
        console.write('set THREADS {0}'.format(THREADS))    
    console.write('run -j')
    result = list()
    while True:
        sleep(5)
        r = console.read()
        if(len(r['data']) > 0):
            print(r['data'])
            for line in r['data'].split('\n'):
                if('support' in line):
                    line = line[line.find('-') + 1 : line.find('support')]
                    result.append(line.strip())
        if('100%' in str(r)):
            return result
        if('failed' in str(r)):
            return result


# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    # autoadd is easiest, but one can be more specific:
    print(run(client, '192.168.181.100-254'))