# Information
CLI-tool for Carbon Black Response written in python3, using `cbapi` wrapper library to query Carbon Black server instance's REST API. 

# Prerequisites
**From pip3:**    
 * cbapi
 * argparse

**API credentials**

In order to perform any queries via the API, you will need to get the API token for your CB user. This can be fetched from the CBR GUI.
Once you acquire your API token, place it in one of the default credentials file locations:
 * /etc/carbonblack/
 * ~/.carbonblack/
 * /current_working_directory/.carbonblack/

The credentials are stored in INI format. The name of each credential profile is enclosed in square brackets, followed by key-value pairs providing the necessary credential information:

```
[instance-0]
url=https://local-hosted-instance
token=abcdef0123456789abcdef
ssl_verify=False
proxy=https://10.10.10.10:1234

[instance-1]
url=https://cbserver.prod.corp.com
token=aaaaaa
ssl_verify=True

[instance-2]
url=https://localhost
token=bbbbbb
ssl_verify=False
```

If you want to use the `-a` switch on this tool to sweep all instances with the query you need to create file `instances.txt` in the same directory where `cbr-search.py` is. To do this quickly, just run this hacky one-liner.

    awk -F "[][]" '{print $2}' ~/.carbonblack/credentials.response |strings > instances.txt

Verify the content and it should look like this:
```
instance-0
instance-1
instance-2
```

# Usage
```
usage: cbr-search.py [-h] [-ho HOSTNAME] [-st TMPSTARTTIME] [-et TMPENDTIME]
                     [-n] [-i] [-a] [-m M] [-w W] [--show SHOW]
                     instance

positional arguments:
  instance          instance name

optional arguments:
  -h, --help        show this help message and exit
  -ho HOSTNAME      hostname to search
  -st TMPSTARTTIME  starttime
  -et TMPENDTIME    endtime
  -n                list process netconns
  -i                interactive mode
  -a                sweep mode
  -m M              without the switch you enter CBR cli
                    supported modes:
                          ps      = search powershell processes
                          domain  = manually enter domains or with --wordlist
                          ip      = manually enter ips or with --wordlist

  -w W              load an IOC wordlist (domain and ip modes)
                    NOTE: one entry per line
  --show SHOW
                    supported values:
                          searchterms = show available search terms for free search
```


## Examples
**Sweep all instances with an IOC wordlist**

    python3 cbr-search.py instance-2 -st 4320 -a -m domain -w ../IOC/dealply.txt
  
 * Note that the instance argument is always required even if using -a switch.. i'm too lazy on that :)

**Do a free query on a host and show network connections from the process**
    
    python3 cbr-search.py instance-2 -st 4320 -ho NX-609 -n

**Do a free query on all instances**
    
    python3 cbr-search.py instance-2 -st 4320 -a

**Interactive mode, note that you can use -a switch to sweep all instances, otherwise it will reset back to False after a search if manually switched to 'All instances mode' in interactive mode.** 
    
    python3 cbr-search.py instance-2 -st 20000 -i -a

```
    ____             __                            __  _   _ _  _
   / __ \__  _______/ /___  ____  __   _   _____  / /_(_)_(_|_)(_)
  / /_/ / / / / ___/ __/ / / / / / /  | | / / _ \/ __/ __ `/ _ |
 / ____/ /_/ (__  ) /_/ /_/ / /_/ /   | |/ /  __/ /_/ /_/ / __ |
/_/    \__, /____/\__/\__, /\__, /    |___/\___/\__/\__,_/_/ |_|
      /____/         /____//____/

v0.0.2 by sanre
Start time:2020-02-01T22:49:29
End time:2020-02-15T20:09:29
All instances mode: True
[0] General
[1] Persistence
[2] Credential Access
[3] Powershell
[4] Emotet
[5] LOLBINS
[6] Free search
[7] Toggle sweep mode (all instances or only the current)
CBR>
```

**NOTE for lazy people like myself:**
I recommend using `rlwrap` or similar readline wrapper to have command history and completion within CLI.. :)
https://linux.die.net/man/1/rlwrap