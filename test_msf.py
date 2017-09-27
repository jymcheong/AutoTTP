" make sure all the modules can import/load"
from autocomplete.msf_exploit import exploit
from autocomplete.msf_post import post
from autocomplete.msf_payload import payload

# there may be illegal characters, especially within options class variables
# the import will fail there are illegal characters within class
# print some stuff
print(payload.windows_meterpreter_reverse_https.path)
print(exploit.windows_winrm_winrm_script_exec.path)
print(post.windows_capture_keylog_recorder.path)