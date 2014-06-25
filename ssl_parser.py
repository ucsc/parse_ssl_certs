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
    split_line = re.split(',|\||\n',line)
    if len(split_line) > 14:
      pdb.set_trace()
      IP =  split_line[0]
      LOGICALSEG = ' '.join(split_line[1].split(" ")[0:2])
      TYPE = split_line[8].split(':')[1]
      BITS = split_line[9].split(':')[1]
      COMNAME = split_line[2].split('=')[1]
      ORGNAME = split_line[3].split('=')[1]
      STATE = split_line[6].split('=')[1]
      COUNTRY = split_line[7].split('=')[1]
      BEFORE = datetime.datetime.fromtimestamp(time.mktime(time.strptime\
               (split_line[13].strip(),"%d %b %Y %H:%M:%S %Z")))\
                .strftime("%m/%d %Y").lstrip('0')
      AFTER = datetime.datetime.fromtimestamp(time.mktime(time.strptime\
               (split_line[11].strip(),"%d %b %Y %H:%M:%S %Z")))\
                .strftime("%m/%d %Y").lstrip('0')
      ISSUER = split_line[2].split('=')[1]
      SELFSIGN = split_line[14].split(':')[1]
      VALIDSIG = split_line[-2].split(':')[1][:-1]
      print IP
      print LOGICALSEG
      print TYPE
      print BITS
      print COMNAME
      print ORGNAME
      print STATE
      print COUNTRY
      print BEFORE
      print AFTER
      print ISSUER
      print SELFSIGN
      print VALIDSIG

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
