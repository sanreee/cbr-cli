# -*- coding: utf-8 -*-
'''
Examples:

Sweep all instances with an IOC wordlist
  python3 cbr-search.py instance-2 -st 4320 -a -m domain -w ../IOC/dealply.txt
  Note that the instance argument is always required even if using -a switch.. i'm too lazy on that :)

Do a free query on a host
  python3 cbr-search.py instance-2 -st 4320 -ho WIN10

Do a free query on all instances
  python3 cbr-search.py instance-2 -st 4320 -a

Interactive mode, note that you can specify -a switch to sweep all instances, otherwise it will reset back to False after a search if manually switched to 'All instances mode' in interactive mode.
  python3 cbr-search.py instance-2 -st 4320 -i
'''
from cbapi.response import CbResponseAPI, Process, Binary, Sensor, Alert
from datetime import datetime, timedelta
from menuhelpers import *
import argparse
import sys
import os
import concurrent.futures

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
parser.add_argument("instance", help="Instance name")
parser.add_argument("-ho", help="Hostname to search", default="*", dest='hostname')
parser.add_argument("-st", help="Start time", default=10, dest='tmpstarttime')
parser.add_argument("-et", help="End time", default=0, dest='tmpendtime')
parser.add_argument("-n", help="List process netconns", action='store_true')
parser.add_argument("-i", help="Interactive mode", action='store_true')
parser.add_argument("-a", help="Sweep mode. When declared, it goes through all instances in instances.txt", action='store_true')
parser.add_argument("-c", help="List child processes, default n=1", default=0)
parser.add_argument("-A", help="List alerts :: e.g. type report_score:[90 TO *] when prompted. Currently works only without -a (all instances mode)!", action='store_true')
parser.add_argument("-m", help='''R|Choose between following modes:
      domain  = Manually enter domains or with -W (wordlist)
      ip      = Manually enter IPs or with -W (wordlist)
      ''', default="")
parser.add_argument("-w", help="R|Load an IOC wordlist (domain and ip modes)\nNOTE: one entry per line")
parser.add_argument("--show", help='''R|
Supported values:
      searchterms = Show available search terms for free search
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
  print(colorize('v1.0.1 by sanre','green'))
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
alert_bool = False

# If script is launched with -a switch (sweep mode), all instances are queried
# Example, sweep with an IOC wordlist:
# python3 cbr-search.py instance-2 -st 4320 -a -m domain -w ../IOC/dealply.txt
#
# Note that the instance argument is always required even if using -a switch.. i'm too lazy on that :)
if args.a is True:
  sweepMode ^= True

if args.A is True:
  alert_bool ^= True

def listAlerts(q):
  cb = CbResponseAPI(profile=args.instance)
  alerts = cb.select(Alert).where('hostname:' + args.hostname + ' AND ('+q+') AND created_time:['+ starttime +  ' TO ' + endtime + ']')
  for alert in alerts:
    if 'binary' in alert.alert_type:
      print("{0} - SCORE: \033[32m{1:d}\033[m - HOST: \033[32m{2:s}\033[m - \033[33mBINARY\033[m: {3:s} - REPORT: {4:s}".format(alert.created_time, alert.report_score, alert.hostname, alert.md5, alert.watchlist_name))
    else:
      print("{0} - SCORE: \033[32m{1:d}\033[m - HOST: \033[32m{2:s}\033[m - \033[31mPROCESS\033[m: {3:s} - REPORT: {4:s}".format(alert.created_time, alert.report_score, alert.hostname, alert.process_name, alert.watchlist_name))
      print("\033[1;30;40m{0:s}\033[m".format(alert.process.webui_link)) 

def visitor(proc, depth):
  try:
      start_time = proc.start or "<unknown>"
      end_time = proc.end or "<unknown>"
      entries = ""
      entries += "\033[1;30;40m\033[32m{0}\033{1}: {2} {3}\033[m".format('  -> '*(depth + 1), start_time, proc.cmdline, "(suppressed)" if proc.suppressed_process else "")

  except Exception as e:
      print("** Encountered error while walking children: {0:s}".format(str(e)))
  finally:
    print(entries)

def doTheNeedful(q, sweepMode, alert_bool):
  if sweepMode == True:
    # Load instances
    instances = readInstances()
    args = ((q, instance) for instance in instances)
    # Multithread through customers, gotta go fast
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
      for result in executor.map(lambda p: tempAll(*p), args):
        if q != "MAGIC":
          pass
        else:
          print(result)

  elif alert_bool is True:
    listAlerts(q)

  # Single instance, not threaded
  else:
    tempSingle(q)
  
  input(colorize('Press enter to continue.', 'blue'))
  clearPrompt()
  mainMenu()

def tempSingle(q):
  cb = CbResponseAPI(profile=args.instance)
  query = cb.select(Process).where('hostname:' + args.hostname +' AND ('+q+') AND start:['+ starttime +  ' TO ' + endtime + ']').sort("start asc").max_children(args.c)
  for proc in query:
    print("{0} {1} {2} {3}\n\033[1;30;40m{4}\033[m".format(proc.start, proc.hostname, proc.username, proc.cmdline, proc.webui_link))
    # Show netconns switch
    if args.n is True:
      # Iterate the CB netconns object
      for conns in proc.netconns:
        print("\033[32m{0}\033[m".format(conns))
      continue
    # Show child processes switch
    elif int(args.c) > 0:
      # Iterate the child processes
      proc.walk_children(visitor)

def tempAll(q,instance):

    print(instance.strip())
    #print(q)
    cb = CbResponseAPI(profile=instance.strip())
    query = cb.select(Process).where('hostname:' + args.hostname +' AND ('+q+') AND start:['+ starttime +  ' TO ' + endtime + ']').sort("start asc").max_children(args.c)
    for proc in query:
      print("{0} {1} {2} {3} {4} \n\033[1;30;40m{5}\033[m".format(proc.start, instance.strip(), proc.hostname, proc.username, proc.cmdline, proc.webui_link))
      # Show netconns switch
      if args.n is True:
        # Iterate the CB netconns object
        for conns in proc.netconns:
          print("\033[32m{0}\033[m".format(conns))
      # Show child processes switch
      elif int(args.c) > 0:
        # Iterate the child processes
        proc.walk_children(visitor)

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
          elif b == "menu_discovery"    : initMenu(menu_discovery, sweepMode)
          elif b == "menu_execution"    : initMenu(menu_execution, sweepMode)
          elif b == "menu_persistence"  : initMenu(menu_persistence, sweepMode)
          elif b == "menu_creds"        : initMenu(menu_creds, sweepMode)
          elif b == "menu_lateral"      : initMenu(menu_lateral, sweepMode)
          elif b == "menu_evasion"      : initMenu(menu_evasion, sweepMode)
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
      asd = asd
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

# Maybe develop a way to run queries by selecting them or all by once.
            
            else:
              doTheNeedful(b,sweepMode,alert_bool)


      except (ValueError, IndexError):
        pass

def freeSearch(sweepMode):
  clearPrompt()
  printBanner()
  print(colorize('All instances mode: '+str(sweepMode),'blue'))
  freesearch = input("CBR> ")
  q = freesearch
  doTheNeedful(q,sweepMode,alert_bool)

# Mode (domain) switch
if args.m == "domain":
  # Wordlist switch
  if args.w is not None:
    domains = readWordlist()
    q = '(domain:'+domains+')'
    doTheNeedful(q,sweepMode,alert_bool)
  else:
    domains = input("Domains separated with 'OR': ")
    q = '(domain:'+domains+')'
    doTheNeedful(q,sweepMode,alert_bool)

# Mode (IP) switch
elif args.m == "ip":
  # Wordlist switch
  if args.w is not None:
    ips = readWordlist()
    q = '(ipaddr:'+ips+')'
    doTheNeedful(q,sweepMode,alert_bool)
  else:
    ips = input("IPs separated with 'OR': ")
    q = '(ipaddr:'+ips+')'

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
