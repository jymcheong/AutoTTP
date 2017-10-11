"""
todo enumerate network printers especially MFPs
Get-WMIObject -Class Win32_Printer -Computer $env:computername | Select Name,DriverName,PortName,Shared,ShareName | ft -auto
"""