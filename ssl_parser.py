import csv, sys
import os
import re
import datetime, time
import pdb
"""
--- Issuer/CA
--- self-signed
--- key/bit size
--- issue date/valid from
--- expiration date/valid until
--- host name/CN
--- IP
thumbprint hash
cert type (SSL, wildcard, ucc, san)
--- org name
XXX org city [Not in cert]
--- org state
--- org country
XXX contact name [Not in cert]
"""

"""
usr_input = raw_input("Please select the type of file to parse"\
                      " [nmap(raw)|csv(nexpose)]")
if "nmap" not in usr_input or "csv" not in usr_input:
  print "Input did not specify csv or nmap file Input: %s" % usr_input
  exit(1)
file_input = raw_input("Please enter the file name to parse.")
if not os.path.isfile(file_input):
  print "File not found: %s" % file_input
  exit(1)
file_output = raw_input("Please enter the name of the output file [w/o suff].")
if not file_output or len(file_output) > 14:
  print "File too long [>14 char] or not given" % file_output
  exit(1)
"""
file_input = "nexpose.csv"
file_output = "results"
usr_input = "csv"
nmap_file = open(file_input,'r')
csv_file = open(file_output+'.csv','wb')
csv_write = csv.writer(csv_file, delimiter=',', quotechar='"',\
                        quoting=csv.QUOTE_ALL)
csv_write.writerow(["File: %s" % file_input])
csv_write.writerow(["IP","Hostname", "Alg", "Bits", "Cert Name","Org Name",\
                    "State","Country","Cert Start", "Cert Expiration",\
                     "Issuer", "MD5", "SHA1"])

if ("csv" in usr_input):
  for line in nmap_file:
    #split_line = re.split(',|\||\n',line)
    split_line = re.split('\n',line)
    for part_line in split_line:
      if len(part_line.split(',')) < 10:
        continue
      IP = part_line.split(',')[0]
      LOGICALSEG = ' '.join(part_line.split(',')[1].split(" ")[0:2])

      EXTRA = []

      RE_TYPE = re.compile(r'ssl\.cert\.key\.alg\.name\:(.*?)\|')
      RE_BITS = re.compile(r'ssl\.cert\.key\.rsa\.modulusBits\:(.+?)\|') 
      RE_AFTER = re.compile(r'ssl\.cert\.not\.valid\.after\:\w+, (.+?)\|')
      RE_BEFORE = re.compile(r'ssl\.cert\.not\.valid\.before\:\w+, (.+?)\|')
      RE_ISSUER = re.compile(r'ssl\.cert\.issuer\.dn\:(.+?)\|')
      RE_ERROR = re.compile(r'ssl\.cert\.chainerror\:(.+?)\|')
      RE_SELFSIGN = re.compile(r'ssl\.cert\.selfsigned\:(.+?)\|')
      RE_VALIDSIGN = re.compile(r'ssl\.cert\.validchain\:(.+?)\|')
      
      TYPE = ''.join(RE_TYPE.findall(part_line)).strip()
      BITS = ''.join(RE_BITS.findall(part_line)).strip()
      ERROR = ''.join(RE_ERROR.findall(part_line))
      SELFSIGN = ''.join(RE_SELFSIGN.findall(part_line))
      VALIDSIGN = ''.join(RE_VALIDSIGN.findall(part_line))

      A_ISSUER = ''.join(RE_ISSUER.findall(part_line))
      ISSUER = ""
      ORGNAME = ""
      ORGUNIT = ""
      STATE = ""
      COUNTRY = ""
      CITY=""
      EMAIL =""
      for a in A_ISSUER.split(','):
        if "CN=" in a:
          ISSUER = a.split('CN=')[1]
        elif "OU=" in a:
          ORGUNIT = a.split('OU=')[1]
        elif "O=" in a:
          ORGNAME = a.split('O=')[1]
        elif "L=" in a:
          CITY = a.split('L=')[1]
        elif "ST=" in a:
          STATE = a.split('ST=')[1]
        elif "C=" in a:
          COUNTRY = a.split('C=')[1] 
        elif "EMAILADDRESS=" in a:
          EMAIL = a.split('EMAILADDRESS=')[1]



      if (len(RE_AFTER.findall(part_line)) == 1 ):
        AFTER_RAW = ''.join(RE_AFTER.findall(part_line)).strip()
        AFTER = datetime.datetime.fromtimestamp(time.mktime(time.strptime\
                 (AFTER_RAW.strip(),"%d %b %Y %H:%M:%S %Z")))\
                  .strftime("%m/%d %Y").lstrip('0')
        BEFORE_RAW = ''.join(RE_BEFORE.findall(part_line)).strip()
        BEFORE = datetime.datetime.fromtimestamp(time.mktime(time.strptime\
                 (BEFORE_RAW.strip(),"%d %b %Y %H:%M:%S %Z")))\
                  .strftime("%m/%d %Y").lstrip('0')
       
      else:
        IP = "*** " + IP + " ***" 
        EXTRA = []
        for x in xrange(0, len(RE_AFTER.findall(part_line))):
          AFTER_RAW = RE_AFTER.findall(part_line)
          AFTER = datetime.datetime.fromtimestamp(time.mktime(time.strptime\
                   (AFTER_RAW[x].strip(),"%d %b %Y %H:%M:%S %Z")))\
                    .strftime("%m/%d %Y").lstrip('0')
          BEFORE_RAW = RE_BEFORE.findall(part_line)
          BEFORE = datetime.datetime.fromtimestamp(time.mktime(time.strptime\
                   (BEFORE_RAW[x].strip(),"%d %b %Y %H:%M:%S %Z")))\
                    .strftime("%m/%d %Y").lstrip('0')
          EXTRA += [BEFORE, AFTER]


      #    ## create list of list with order types indexed by for loop
        """
        print ''
        print IP+', '+LOGICALSEG
        print ERROR
        print TYPE+', '+ BITS
        print BEFORE+', '+ AFTER
        print ISSUER+', '+ ORGNAME+', '+ ORGUNIT
        print 'Loc: '+CITY+', '+ STATE+', '+COUNTRY
        print 'Sig: '+SELFSIGN+', '+VALIDSIGN
        print ''
        """

if ("nmap" in usr_input):
  each_host = []
  temp_host = []
  for line in nmap_file:
    if line[0] == "#":
      continue 
    if line[0] == '\n':
      IP =  ""
      HOSTNAME = ""
      TYPE = ""
      BITS = ""
      COMNAME = []
      ORGNAME = []
      STATE = [] 
      COUNTRY = []
      BEFORE = []
      AFTER = []
      ISSUER = []
      MD5 = []
      SHA1 = []
      for line in temp_host:
        if "Nmap scan report" in line:
          ## remove newline and other paren
          if len(line.split("(")) > 1:
            HOSTNAME = line.split(" ")[4]
            IP = line.split("(")[1][:-1]
          else:
            IP = line.split(" ")[-1]
            HOSTNAME = ""
        elif "Public Key type" in line:
          TYPE = line.split(':')[1].strip()
        elif "Public Key bits" in line:
          BITS = line.split(':')[1].strip()
        elif "Not valid before" in line:
          temp = line.split(':')[1].split(' ')[1]
          if temp == "Can't":
            temp = line.split(' ')[-1]
          BEFORE.append(temp)
        elif "Not valid after" in line:
          ## two spaces...
          temp = line.split(':')[1].split(' ')[2]
          if temp == "Can't":
            temp = line.split(' ')[-1]
          AFTER.append(temp)
          
        elif "Subject" in line:
          if (len(line.split('/'))> 1):
            comname = line.split('/')[0].split('=')[1]
            orgname = line.split('/')[1].split('=')[1]
            state = line.split('/')[-2].split('=')[1]
            country = line.split('/')[-1].split('=')[1]
          else:
            comname = line.split('=')[1]
            orgname = "Not Stated"
            state = "Not Stated"
            country = "Not Stated"

          if state == "SomeState":
            state = "Not Stated"
          if orgname == "SomeOrganization":
            orgname = "Not Stated"
          if country == "--":
            country = "Not Stated"
          COMNAME.append(comname)
          ORGNAME.append(orgname)
          STATE.append(state)
          COUNTRY.append(country)
        elif "Issuer" in line:
          if (len(line.split('/'))> 1):
            issuer = line.split('/')[0].split('=')[1]
          else:
            issuer = line.split('=')[1]
          if ("localhost" in issuer) or (COMNAME[-1] == issuer):
            issuer = "Self Signed"
          ISSUER.append(issuer)
        elif "MD5" in line:
          MD5.append(line.split(':')[1].strip())
        elif "SHA-1" in line:
          SHA1.append(line.split(':')[1].strip())
      this_host = [IP, HOSTNAME, TYPE, BITS]
      repeatable = [COMNAME, ORGNAME, STATE, COUNTRY,\
                  BEFORE, AFTER, ISSUER, MD5, SHA1]
      STR = []
      print range(0,len(COMNAME))
      print COMNAME
      for x in range(0,len(COMNAME)):
        for y in repeatable:
          print y,x
          STR.append(''.join(y[x]))
        print STR
      this_host += STR
      #each_host.append(temp_host)
      if COMNAME and ISSUER:
        csv_write.writerow(this_host)
      temp_host = []
      continue
    temp_host.append(line.strip())
