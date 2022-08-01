#!/usr/bin/python
import xml.etree.ElementTree as treant
from termcolor import colored
import requests

import warnings
# to hide requests warnings
warnings.simplefilter("ignore")

def containsNumber(value):
 for character in value:
  if character.isdigit():
   return True
 return False

def fix_cpe_str(str):
  str=str.replace('-',':')
  return str

def risk_color(risk):
  if "LOW" in risk:
    return colored(risk,"green")
  if "MEDIUM" in risk:
    return colored(risk,"yellow")
  if "HIGH" in risk:
    return colored(risk,"red")
  if "CRITICAL" in risk:
    return colored(risk,"red",attrs=['blink'])


def txtoutput(r,port,cpe,limit,host):
  print (colored("Host: "+host,"cyan"))
  print (colored("Port: "+port,"cyan"))
  print (colored(cpe+"\n","cyan"))
  counter=4
  check_table=0
# SAX Style parse 
  for line in r.iter_lines():
    line=str(line)
    if len(line) and limit != 0:
      if check_table == 0:
        if "vuln-results" in line:
          check_table=1
      if check_table:
        if "href=\"/vuln/detail/" in line:
          cve=line.split('"')
          cve_url="https://nvd.nist.gov"+cve[1]
          print ("\tURL: "+colored(cve_url,"yellow"))
          counter-=1
        if "vuln-summary" in line:
          desc_parse=line.split('>')
          description=desc_parse[1][:-3]
          print ("\tDescription: "+colored(description+"\n","green"))
          counter-=1
        if "vuln-cvss3-link-" in line:
          risk1_parse=line.split('>')
          risk1=risk1_parse[1][:-3]
          print ("\tRisk cvss-3: "+risk_color(risk1)+"\n")
          counter-=1
        if "vuln-cvss2-link-" in line:
          risk2_parse=line.split('>')
          risk2=risk2_parse[1][:-3]
          print ("\tRisk cvss-2: "+risk_color(risk2)+"\n")
          counter-=1
        if counter == 0:
          limit-=1
          counter=4
        if "pagination\-nav\-container" in line:
          return;
          
  return;

def xmloutput(r,port,cpe,limit,host):
  print ("\n<vision>\n\t<host>"+host+"</host>\n\t<port>"+port+"</port>\n")
  print ("\t<cpe>"+cpe+"</cpe>\n")
  counter=4
  check_table=0
# SAX parse Style
  for line2 in r.iter_lines():
    line2=str(line2)
    if line2 and limit != 0: 
      if check_table == 0:
        if "vuln-results" in line2:
          check_table=1
      if check_table:
        if "href=\"/vuln/detail/" in line2:
          cve=line2.split('"')
          cve_url="https://nvd.nist.gov"+cve[1]
          print ("\t<cve> "+cve_url+"</cve>")
          counter-=1  
        if "vuln-summary" in line2:
          desc_parse=line2.split('>')
          description=desc_parse[1][:-3]
          print ("\t<description> "+description+"</description>\n")
          counter-=1
        if "vuln-cvss3-link-" in line:
          risk1_parse=line.split('>')
          risk1=risk1_parse[1][:-3]
          print ("\t<cvss-3>"+risk1+"</cvss-3>\n")
          counter-=1
        if "vuln-cvss2-link-" in line:
          risk2_parse=line.split('>')
          risk2=risk2_parse[1][:-3]
          print ("\t<cvss-2>"+risk2+"</cvss-2>\n")
          counter-=1
        if counter == 0:
          limit-=1
          counter=4
        if "pagination\-nav\-container" in line2:
          print ("</vision>")
          return;

  print ("</vision>")
  return;

def prepare_cpe(cpe):
 if containsNumber(cpe) == True:
   word=cpe.split(':')
   name=word[2]
   types=word[3]
   if len(word) >= 5:
    version=word[4]
    ret=name+" "+types+" "+version
    return ret
   return 0 
 return 0



def nmap_xml_parse(file_input,limit,type_output):
    print ("\n::::: Vision v0.3 - nmap NVD's cpe correlation with CVE - Coded by CoolerVoid\n")
    tree = treant.parse(file_input)
    root = tree.getroot()
    counter=1
  
    if len(type_output)>3:
      print ("Error: choice one output type, xml or txt...\n")
      exit(0)
  
    for child in root.findall('host'):
            for k in child.findall('address'):
                host = k.attrib['addr']
            for y in child.findall('ports/port'):
                current_port = y.attrib['portid']
                for z in y.findall('service/cpe'):

                  if len(z.text)>4:
                    cpe=fix_cpe_str(z.text)
                    cpe=prepare_cpe(cpe)
                    if cpe != 0:     
                      URL_mount="https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query="+cpe+"&search_type=all&isCpeNameSearch=false"
                      print("Find CPE : "+str(cpe))
                      r = requests.get(URL_mount,stream=True)
                      if(r.status_code == 200):
                        if type_output == "txt" and counter == 1:
                          txtoutput(r,current_port,cpe,limit,host)
                          counter=0
            
                        if type_output == "xml" and counter ==1:
                          xmloutput(r,current_port,cpe,limit,host)
            
                        counter=1;
          
                      else:
                        print ("\n Problem in NVD NIST server\n")
                        exit(0)
                      z.text=""
