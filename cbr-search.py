# -*- coding: utf-8 -*-
'''
Examples:

Sweep all instances with an IOC wordlist
  python3 cbr-search.py instance-2 -st 4320 -a -m domain -w ../IOC/dealply.txt
  Note that the instance argument is always required even if using -a switch.. i'm too lazy on that :)

Do a free query on a host
  python3 cbr-search.py instance-2 -st 4320 -ho NX-609

Do a free query on all instances
  python3 cbr-search.py instance-2 -st 4320 -a

Interactive mode, note that you can specify -a switch to sweep all instances, otherwise it will reset back to False after a search if manually switched to 'All instances mode' in interactive mode.
  python3 cbr-search.py instance-2 -st 4320 -i
'''
from cbapi.response import CbResponseAPI, Process, Binary, Sensor
from datetime import datetime, timedelta
from menuhelpers import *
import argparse
import sys
import os

header = "\
    ____             __                            __  _   _ _  _ \n\
   / __ \__  _______/ /___  ____  __   _   _____  / /_(_)_(_|_)(_)\n\
  / /_/ / / / / ___/ __/ / / / / / /  | | / / _ \/ __/ __ `/ _ |  \n\
 / ____/ /_/ (__  ) /_/ /_/ / /_/ /   | |/ /  __/ /_/ /_/ / __ |  \n\
/_/    \__, /____/\__/\__, /\__, /    |___/\___/\__/\__,_/_/ |_|  \n\
      /____/         /____//____/                                 \n"

class ParserClass(argparse.ArgumentParser):
  def error(self, message):
    sys.stderr.write('error: %s\n' % message)
    self.print_help()
    sys.exit(2)

class SmartFormatter(argparse.HelpFormatter):
  def _split_lines(self, text, width):
    if text.startswith('R|'):
      return text[2:].splitlines()
    return argparse.HelpFormatter._split_lines(self, text, width)

parser = ParserClass(formatter_class=SmartFormatter)
parser.add_argument("instance", help="instance name")
parser.add_argument("-ho", help="hostname to search", default="*", dest='hostname')
parser.add_argument("-st", help="starttime", default=10, dest='tmpstarttime')
parser.add_argument("-et", help="endtime", default=0, dest='tmpendtime')
parser.add_argument("-n", help="list process netconns", action='store_true')
parser.add_argument("-i", help="interactive mode", action='store_true')
parser.add_argument("-a", help="sweep mode", action='store_true')
parser.add_argument("-m", help='''R|without the switch you enter CBR cli
supported modes:
      ps      = search powershell processes
      domain  = manually enter domains or with --wordlist
      ip      = manually enter ips or with --wordlist
      ''', default="")
parser.add_argument("-w", help="R|load an IOC wordlist (domain and ip modes)\nNOTE: one entry per line")
parser.add_argument("--show", help='''R|
supported values:
      searchterms = show available search terms for free search
      ''')

colors = {
        'blue': '\033[94m',
        'pink': '\033[95m',
        'green': '\033[92m',
        }
 
def colorize(string, color):
    if not color in colors: return string
    return colors[color] + string + '\033[0m'

def printBanner():
  print(colorize(header,'pink'))
  print(colorize('v0.0.2 by sanre','green'))
  print("Start time:" + str(starttime))
  print("End time:" + str(endtime))
  
def clearPrompt():
   print("\x1B[2J")

args = parser.parse_args()
#print(args.tmpstarttime)	#DEBUG print
starttime = datetime.utcnow()-timedelta(minutes=int(args.tmpstarttime))
starttime = starttime.strftime("%Y-%m-%dT%H:%M:%S")
print("Start time:" + str(starttime))
endtime = datetime.utcnow()-timedelta(minutes=int(args.tmpendtime))
endtime = endtime.strftime("%Y-%m-%dT%H:%M:%S")
opt = ''
asd = None
sweepMode = False

# If script is launched with -a switch (sweep mode), all instances are queried 
# Example, sweep with an IOC wordlist:
# python3 cbr-search.py instance-2 -st 4320 -a -m domain -w ../IOC/dealply.txt
#
# Note that the instance argument is always required even if using -a switch.. i'm too lazy on that :)
if args.a is True:
  sweepMode ^= True 

def doTheNeedful(q, sweepMode):
  if sweepMode == True:
    #load instances
    instances = readInstances()
    #print("instances: "+instances)
    for jee in instances:
      print(jee)
      cb = CbResponseAPI(profile=jee.strip())
      query = cb.select(Process).where('hostname:' + args.hostname +' AND '+q+' AND start:['+ starttime +  ' TO ' + endtime + ']').sort("start asc")
      for proc in query:
        print("{0} {1} {2}\n\033[1;30;40m{3}\033[m".format(proc.start, proc.hostname, proc.cmdline, proc.webui_link))
        if args.n is True:
          for conns in proc.netconns:
            print("\033[32m{0}\033[m".format(conns))
  else:
    cb = CbResponseAPI(profile=args.instance)
    query = cb.select(Process).where('hostname:' + args.hostname +' AND '+q+' AND start:['+ starttime +  ' TO ' + endtime + ']').sort("start asc")
    for proc in query:
      print("{0} {1} {2}\n\033[1;30;40m{3}\033[m".format(proc.start, proc.hostname, proc.cmdline, proc.webui_link))
      # Show netconns switch
      if args.n is True:
        # Iterate the CB netconns object
        for conns in proc.netconns:
          print("\033[32m{0}\033[m".format(conns))
  input(colorize('Press enter to continue.', 'blue'))
  clearPrompt()
  mainMenu()

def readInstances():
  wl = open("instances.txt","r")
  content = wl.readlines()
  #print(content)      # DEBUG print
  wl.close()
  return content

def readWordlist():
  print("wordlist: %s" % args.w)
  with open(args.w, "r") as wl:
    content = wl.read()
    content = os.linesep.join([s for s in content.splitlines() if s])
    parsed_wl = content.replace("\n"," OR ")
#    print(parsed_wl)      # DEBUG print
    return parsed_wl

# MAIN MENU
def mainMenu(sweepMode=sweepMode):
  while True:
    clearPrompt()
    printBanner()
    print(colorize('All instances mode: '+str(sweepMode),'blue'))
    for item in menu_main:
      print("\033[32m[{0}]\033[m {1}".format(list(menu_main.keys()).index(item),item))
    try:
      opt = int(input("CBR> "))
      if int(opt) < 0 : raise ValueError
      for i, (a,b) in enumerate(menu_main.items()):
        if i == opt:
          if b == "menu_general"        : initMenu(menu_general, sweepMode)
          elif b == "menu_persistence"  : initMenu(menu_persistence, sweepMode)
          elif b == "menu_creds"        : initMenu(menu_creds, sweepMode)
          elif b == "menu_powershell"   : initMenu(menu_powershell, sweepMode)
          elif b == "menu_emotet"       : initMenu(menu_emotet, sweepMode)
          elif b == "menu_lolbins"      : initMenu(menu_lolbins, sweepMode)
          elif b == "free_search"       : freeSearch(sweepMode)
          elif b == "toggle_sweep"      : sweepMode^=True
    except (ValueError, IndexError):
      pass

# MENU HANDLER
def initMenu(b, sweepMode, asd=asd):
  while True:
    if (asd is None):
      asd = b
    elif type(b) == dict: mainMenu()
    else:
      clearPrompt()
      printBanner()
      print(colorize('All instances mode: '+str(sweepMode),'blue'))
      for item in asd:
        print("\033[32m[{0}]\033[m {1}".format(list(asd.keys()).index(item),item))
      try:
        opt = int(input("CBR> "))
        if int(opt) < 0 : raise ValueError
        for i, (a,b) in enumerate(b.items()):
          if i == opt:
            if b == "back" : mainMenu()
            else : doTheNeedful(b,sweepMode)
      except (ValueError, IndexError):
        pass

def freeSearch(sweepMode):
  clearPrompt()
  printBanner()
  print(colorize('All instances mode: '+str(sweepMode),'blue'))
  freesearch = input("CBR> ")
  q = freesearch
  doTheNeedful(q,sweepMode)

# Mode (domain) switch
if args.m == "domain":
  # Wordlist switch
  if args.w is not None:
    domains = readWordlist()
    q = '(domain:'+domains+')'
    doTheNeedful(q,sweepMode)
  else:
    domains = input("Domains separated with 'OR': ")
    q = '(domain:'+domains+')'
    doTheNeedful(q,sweepMode)

# Mode (IP) switch
elif args.m == "ip":
  # Wordlist switch
  if args.w is not None:
    ips = readWordlist()
    q = '(ipaddr:'+ips+')'
    doTheNeedful(q,sweepMode)
  else:
    ips = input("IPs separated with 'OR': ")
    q = '(ipaddr:'+ips+')'

# Mode (powershell) switch
elif args.m == "ps":
  q = 'process_name:powershell.exe'
  doTheNeedful(q,sweepMode)

# Interactive switch
elif args.i == True:
  mainMenu(sweepMode)


elif args.show == "searchterms":
  print('''
  blocked_md5         md5
  blocked_status      status
  childproc_count     count
  childproc_md5       md5
  childproc_name      keyword
  cmdline             cmdline
  company_name        text
  copied_mod_len      count
  crossproc_count     count
  crossproc_md5       md5
  crossproc_name      keyword
  crossproc_type      remote_thread, process_open
  digsig_issuer       text
  digsig_prog_name    text
  digsig_publisher    text
  digsig_result       sign
  digsig_sign_time    datetime
  digsig_subject      text
  domain              domain
  file_desc           text
  file_version        text
  filemod             path
  filemod_count       count
  filewrite_md5       md5
  group               keyword
  has_emet_config     bool
  has_emet_event      bool 
  host_type           keyword
  hostname            keyword
  internal_name       text
  ipaddr              ipaddr
  ipport              integer
  is_64bit            bool
  is_executable_image bool
  last_server_update  datetime
  last_update         datetime
  md5                 md5
  modload             path
  modload_count       count
  netconn_count       count
  observed_filename   path
  orig_mod_len        count
  original_filename   text
  os_type             keyword
  parent_id           long
  parent_md5          md5
  parent_name         keyword
  path                path
  private_build       text
  process_id          long
  process_md5         md5
  process_name        keyword
  product_desc        text
  product_name        text
  product_version     text
  regmod              path
  regmod_count        count
  sensor_id           long
  special_build       text
  start               datetime
  tampered            bool
  username            keyword
  watchlist_<id>      datetime
  ''') 

else:
  freeSearch(sweepMode)

# References:
#   Emotet:
#     https://redcanary.com/blog/stopping-emotet-before-it-moves-laterally/
#     Red Canary. Threat Intelligence - Detecting Emotet (pdf)
#     https://blog.malwarebytes.com/detections/trojan-emotet/
#   LOLBINS
#     https://lolbas-project.github.io/
# TODO:
# Run all mode
#
# Lolbins
#   -runman.exe
#     execute stuff wihout touching the disk

