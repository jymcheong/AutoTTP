from pymetasploit.msfrpc import MsfRpcClient

" On Kali/MSF machine, run $ ./msfrpcd -P test -S -f"
" -S = no ssl, - P = password, -f = foreground"
client = MsfRpcClient('test', server="172.16.199.172", port=55553, ssl=False)

def generate_codes(client, source_code, module_type):    
    if module_type == 'exploit':
        modules = client.modules.exploits
    elif module_type == 'payload':
        modules = client.modules.payloads        
    elif module_type == 'post':
        modules = client.modules.post
    source_code += "\nclass {0}(object):".format(module_type)
    for m in modules:
        if m.startswith('windows'): # so let's limit it to windows for now
            e = client.modules.use(module_type, m)        
            source_code += "\n\tclass {0}(object):".format(m.replace('/', '_'))
            source_code += '\n\t\t"""'
            source_code += "\n\t\t{0}".format(e.description.replace('\\','/'))
            source_code += '\n\t\t"""\n'        
            source_code += "\n\t\tpath = '{0}'".format(m)
            source_code += "\n\t\tclass options(object):"
            for o in e.options:
                key = o.replace("::", '_')
                key = key.replace(' ', '_')
                if o in e.required:                
                    key = 'required_' + key
                source_code += "\n\t\t\t{0} = '{1}'".format(key, o)        
            source_code += "\n"
    return source_code

header = '""" This is generated autocomplete helper class for MSF """'
source_code = generate_codes(client, header, 'payload') 
with open("msf_payload_autocomplete.py", "w") as text_file:
    text_file.write(source_code)
source_code = generate_codes(client, header, 'exploit') 
with open("msf_exploit_autocomplete.py", "w") as text_file:
    text_file.write(source_code)
source_code = generate_codes(client, header, 'post') 
with open("msf_post_autocomplete.py", "w") as text_file:
    text_file.write(source_code)
