import csv, sys

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

nmap_file = open('20140106_nmap_ssl_scan.nmap','r')
csv_file = open('20140106_nmap_ssl_scan.csv','wb')
csv_write = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
csv_write.writerow(["File: 20140106_nmap_ssl_scan.nmap"])
csv_write.writerow(["IP","Hostname", "Alg", "Bits", "Cert Name","Org Name", "State",
                   "Country","Cert Start", "Cert Expiration", "Issuer", "MD5", "SHA1"])
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
