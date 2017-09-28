from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient


client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
sessions = client.sessions.list



pass # for breakpoint