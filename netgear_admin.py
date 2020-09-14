#
# netgear_admin.py
#
# Corey Anderson 
# September 2020
# 
# Usage examples:
#
# Turn OFF port 4
# python3 netgear.py -a 192.168.0.163 -passwd <password> -p 4 -s off
#
# Turn ON port 4
# python3 netgear.py -a 192.168.0.163 -passwd <password> -p 4 -s on
#
# Read status of ports:
# python3 netgear.py -a 192.168.0.163 -passwd <password> -r
#
# Bugs/Issues:
# * Only one port can be toggled per run.
# * The switch returns 'The maximum number of attempts has been reached' errors
#   quite frequently, even when 'sleep_between_calls' 
#   is set to a high value, even 4 seconds
#

import sys

if sys.version_info.major < 3:
    print ("\nError: Python 3 required.\n")
    exit()
    
import re
import argparse
import urllib.request
import hashlib
import json
import time

parser = argparse.ArgumentParser()

parser.add_argument('-v', action='store_true', help='Verbose') # Not used
parser.add_argument('-r', action='store_true', help='Read switch port status') # Not used
parser.add_argument('-a', action='store', dest='switch_addr', required=True, help='IP address of switch')
parser.add_argument('-passwd', action='store', dest='passwd', required=True, help='Admin password of switch')
parser.add_argument('-p', action='store', dest='port', help='Switch Port')
parser.add_argument('-s', action='store', dest='set_status', help='Set Switch Port Status: [on/off]')

global args
global results

args = parser.parse_args()

# Additional Validation:
#
#if len(args.port) and not len(args.store):
if args.port:
    if not args.set_status:
        print ("Error: if -p (port) is specified, -s (status) is also required")
        exit()

    if args.set_status != 'on' and args.set_status != 'off':
        print ("Error: status must be either: on, off")
        exit()

config = { 
           'switch_addr'   : args.switch_addr,
           'passwd'        : args.passwd,
           'port'          : args.port,
           'read_status'   : args.r,              # If True, will also print out the status of the switch ports.
           'set_status'    : args.set_status,
           'rand_val'      : '',                  # The pseudo-random 'rand' field from the switch, used to 'encode' plaintext passwd.
           'hash_val'      : '',                  # An input var produced from the Switch's web server, needed to change status.
           'passwd_merged' : '',                  # The passwd, interleaved with the supplied passwd.
           'passwd_md5'    : '',                  # The md5 hash of passwd_enc, what we'll actually post to the switches web interface.
           'auth_cookie'   : '',                  # The cookie we get back on a successful login.
           'sleep_between_calls' : 4,             # Time in seconds to sleep between HTTP calls
         }

#
# Get the switches 'rand' value:
#
_contents = urllib.request.urlopen("http://%s/" % config['switch_addr']).read().decode("utf-8").replace('\n','')

time.sleep(config['sleep_between_calls'])

    
_tmp = re.findall("^.*<input type=hidden id=\"rand\" name=\"rand\" value='(\d+)' disabled>.*$", _contents)

try:
    _tmp = (_tmp[0])  # De-tuplify, and convert to list

    config['rand_val'] = _tmp

except Exception as ex:
    print ("Error reading 'rand' from switch:", ex)
    exit()


#
# Set passwd_enc by merging plaintext password and our supplied 'rand' value:
#

i = 0

for c in config['rand_val']:
    if i < len(config['passwd']):
        config['passwd_merged'] += config['passwd'][i]
        
    i += 1        
    
    config['passwd_merged'] += c

if i < len(config['passwd']):
    config['passwd_merged'] += config['passwd'][-(len(config['passwd'])-i):]
    

config['passwd_md5'] = hashlib.md5(config['passwd_merged'].encode()).hexdigest()

#
# Attempt to post to login page, so we'll get a session cookie:
#
data = { 
         'password' : config['passwd_md5'],
       }

data = urllib.parse.urlencode(data).encode()

req = urllib.request.Request("http://%s/login.cgi" % config['switch_addr'], data=data)

resp = urllib.request.urlopen(req)

time.sleep(config['sleep_between_calls'])

_success_check = resp

_success_check = _success_check.read().decode("utf-8").replace('\n','')

if 'The password is invalid' in _success_check:
    print ("ERROR: Invalid Password")
    exit()
    
if 'The maximum number of attempts has been reached' in _success_check:
    print ("ERROR: The maximum number of failed attempts has been reached. Wait a few minutes and then try again")
    exit()

# Example cookie:
# GS108SID=K^tecASxwBawbwuJftgrB`n_yGjmr`JYhnFxJ\WmTILVUasWbFduJU\igbX`[GLhUw]_b`LLqZit_\_G; path=/;HttpOnly

_tmp = re.findall("^GS108SID=(.*); path=/;HttpOnly$", str(resp.info()['Set-Cookie']))

try:
    _tmp = (_tmp[0])  # De-tuplify, and convert to list

    config['auth_cookie'] = _tmp

except Exception as ex:
    print ("Error reading Cookie:", ex)
    exit()

if not config['auth_cookie']:
    print ("Unable to get cookie!")
    exit()

#
# Read 'hash' input field from: status.htm
# Example: <input type="hidden" name='hash' id='hash' value='26346'>
#
req = urllib.request.Request("http://%s/status.htm" % config['switch_addr'])
req.add_header("Cookie", "GS108SID=%s" % config['auth_cookie'])

_contents = urllib.request.urlopen(req)

time.sleep(config['sleep_between_calls'])

_success_check = _contents
_success_check = _success_check.read().decode("utf-8")
_status_check_list = _success_check.splitlines()
_success_check = _success_check.replace('\n','')
    
_tmp = re.findall("^.*<input type=\"hidden\" name='hash' id='hash' value='(\d+)'>.*$", _success_check)

try:
    _tmp = (_tmp[0])  # De-tuplify, and convert to list

    config['hash_val'] = _tmp

except Exception as ex:
    print ("Error reading 'hash' from switch:", ex)
    exit()

if config['read_status'] is True:
    print ("port status:")
    
    _tmp_line = 58  # Port 1 starts on line 59

    for p in range (1, 9):
        _p_status = _status_check_list[_tmp_line].replace('<td class="def " sel="select">', "")
    
        print ("Port %d   %s" % (p, _p_status))
        
        _tmp_line += 14

#
# If specified, post the desired status to the desired port:
#
if config['port']:
    _port = 'port' + config['port']
    
    # speed:
    # 1 = Auto
    # 2 = Disable
    # 3 - 6 = Other speed/duplex options
    
    _speed = '1' if config['set_status'] == 'on' else '2'
    
    data = { 
             _port          : 'checked',
             'SPEED'        : _speed,
             'FLOW_CONTROL' : '2',
             'hash'         : config['hash_val'],
           }
    
    data = urllib.parse.urlencode(data).encode()
    
    req = urllib.request.Request("http://%s/status.cgi" % config['switch_addr'], data=data)
    req.add_header("Cookie", "GS108SID=%s" % config['auth_cookie'])
    
    resp = urllib.request.urlopen(req)
    time.sleep(config['sleep_between_calls'])
    
    










