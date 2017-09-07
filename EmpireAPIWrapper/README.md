# EmpireAPIWrapper
A simple Python wrapper for the PowerShell Empire API. 

The wrapper is feature complete as of [Empire's](https://github.com/adaptivethreat/Empire) RESTful API as of Empire 1.5.0.
 
 Start the Empire RESTful server:
 ```bash
 $ ./empire --rest
 
 [*] Loading modules from: /root/Empire/lib/modules/
  * Starting Empire RESTful API on port: 1337
  * RESTful API token: 8uuub6bg4s5whcj8rixx24wamk530lwtenhadooq
  * Running on https://0.0.0.0:1337/ (Press CTRL+C to quit)
 ```
 
 
 Initalize the connection to the Empire server with one of these three calls:
 ```python
 # A username and password
 api = EmpireAPIWrapper.empireAPI('172.16.242.191', uname='empireadmin', passwd='Password123!')
 
 # A token; can be permanent or session generate 
 api = EmpireAPIWrapper.empireAPI('10.15.20.157', token='<token_string_here>')
 ```
 
