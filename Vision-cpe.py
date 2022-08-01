#!/usr/bin/python

import sys, os.path
from parse import parsers


def banner_vision():
 print ("""        ..::: VISION v0.3 :::... 
        Nmap\'s XML result parser and NVD's CPE correlation to search CVE
    
    Example:
        python Vision-cpe.py result_scan.xml 3 txt > log_result.txt

    argv 1 = Nmap scanner results in XML
    argv 2 = Limit CVEs per CPE to get
    argv 3 = Type of output (xml or txt)

                                            Coded by Parth Sharma
""")
 return 


def main(argv):
 if len(sys.argv)==4:
  file_input=sys.argv[1]
  if os.path.exists(file_input):    
   limit=int(sys.argv[2])
   type_output=str(sys.argv[3])
   parsers.nmap_xml_parse(file_input,limit,type_output)
   print("Start parser")
  else:
   print ("Either file is missing or is not readable")
   sys.exit(0)
  sys.exit(0)    
 else:
  print ("\nError needs nmap's XML scan result by passed by first argument\n")
  banner_vision()
 sys.exit(0)

if __name__ == "__main__":
    main(sys.argv)
