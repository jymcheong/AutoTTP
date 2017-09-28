" make sure all the modules can import/load"
from pymetasploit.msfrpc import MsfRpcClient
from c2_settings import MSF_SERVER, MSF_PWD
# there may be illegal characters, especially within options class variables
# the import will fail there are illegal characters within class
# print some stuff

client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)

sessions = client.sessions.list[2]

pass