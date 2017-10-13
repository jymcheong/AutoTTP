"""
This is the so call "scenario" (placeholder), basically a complex procedure to complete a (sub) mission.
In this case, the mission is to leak all print jobs.

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
"""
