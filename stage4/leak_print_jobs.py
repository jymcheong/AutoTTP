"""
This is the so call "scenario" (placeholder), basically a complex procedure to complete a (sub) mission.
In this case, the main objective is to capture all print jobs.

Two possibilities:
1. MFP has internet access
2. MFP has NO internet

Either case, feature-rich MFP usually have admin web UI.
More than users can't be bothered to change default passwords.

If its internal red-teaming, we can emulate a printer configuration change for:
case #1: send all print jobs as PDF to disposal email address under our control
case #2: setup a file-share on the pivot, configure printer to write all jobs to file-share

Latter case is a little more complex but both cases are good illustration of 
internal pivot using port-forwarding to remotely access printer admin UI.

Details: 
https://github.com/RUB-NDS/PRET
http://hacking-printers.net/wiki/index.php/Main_Page

From http://hacking-printers.net/wiki/index.php/Print_job_retention,
we can see that certain printers supporting PostScript can retain jobs.
using a pret shell, it possible to start capture, follow by fetch captured jobs.
Suppose the target printer supports TCP port 9100 printing, a portfwd can be configured
giving the remote attacker a pret shell to perform the attack.
"""