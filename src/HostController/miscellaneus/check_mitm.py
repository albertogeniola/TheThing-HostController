import os
import json
import xml.etree.ElementTree as ET
from colorama import init, Fore, Back, Style
from lxml.etree import XMLParser
import sys
import winsound

PATH="Y:\\OutputReports\\mitm_attack"

if __name__ == '__main__':
    init(autoreset=True)
    
    tampered_files = dict()
    # Load mitm tampered files
    with open("mitm_tampered_files.log", "r") as log:
        data = log.read()
        lines = data.split("\n")
        for l in lines:
            if l.strip() == "":
                continue
            tokens = l.strip().split(';')
            type = tokens[0]
            hash = tokens[1]
            log = ''.join(tokens[2:])
            tampered_files[hash] = (type,log)
            
    print("Loaded %d tampered files." % len(tampered_files.keys()))
    print(Fore.YELLOW+Style.BRIGHT+"Press a key to start the analysis.")
    l = sys.stdin.readline()
    
    while l.strip() != "q":
        dirs = os.listdir(PATH)
        # Print heading line
        print("experiment_id\tOutcome\tAttackMethod\tTrapUrl\tRequestHeaders\tRequestContents\t\rResponseHeaders\tResponse Content-Type\tElevated")
        
        with open("mitm_res.csv", "wt") as f:
            msi=0
            exe=0
            dropped=0
            removed=0
            count = 0
            f.write("Experiment Id\tOutcome\tAttackMethod\tTrapHost\tTrapUrl\tRequestHeaders\tRequestContents\tResponseHeaders\tContent Type\tElevated\n")
            for d in dirs: 
                mitm_file = os.path.join(PATH,d,"mitm.xml")
                parser = XMLParser(ns_clean=True, recover = True)
                xml = ET.parse(mitm_file,parser)
                outcome=None
                attack_url = None
                attack_host = None
                req_headers = None
                res_headers = None
                content_type = None
                req_contents = None
                attack_type = None
                pid = None
                elevated = None
                
                # Retrieve info about the MITM Attack
                mitm = xml.findall(".//MitmAttack")[0]
                success = mitm.find("Success").text
                
                count+=1
                request = None
                reponse = None
                
                if success != "True":
                    # For each file we encountered during the analysis, check its hash and verify if there is any trace of ours injections.
                    files = xml.findall(".//FileStatus")
                    for fi in files:
                        hash = fi.find("Md5Hash").text.strip().lower()
                        if tampered_files.get(hash) is not None:
                            # We have an hit! Check if the file is still there.
                            attack_type = tampered_files.get(hash)[0].upper()
                            log = tampered_files.get(hash)[1]
                            exists = fi.getparent().getparent().attrib['LeftOver']
                            if exists == "True":
                                outcome = "File dropped"
                                dropped += 1
                                mitm = ET.fromstringlist([log],parser=parser)
                                request = mitm.find("./Request")
                                response = mitm.find("./Response")
                            else:
                                outcome = "File removed"
                                removed += 1
                            break
                else:
                    outcome = "Attack successful"
                    pid = mitm.find("ProcessId").text
                    elevated = mitm.find("ProcessElevated").text
                    proc_image_path = mitm.find("ProcessPath").text                   
                    request = mitm.find("NetworkInfo/Flow/Request")
                    response = mitm.find("NetworkInfo/Flow/Response")
                
                if outcome is not None:
                    # Sometimes we get missing network info. For now just skip that info
                    if request is not None:
                        attack_url = request.find("PrettyUrl").text
                        attack_host = request.find("PrettyHost").text
                        # Build headers
                        headers = dict()
                        for h in request.findall(".//Header"):
                            key = h.find("Key").text
                            val = h.find("Value").text
                            headers[key] = val
                        
                        req_headers = ''.join("%s=%s," % (k,v) for k,v in headers.iteritems()).strip(",")
                    
                    # Build headers
                    headers = dict()
                    for h in response.findall(".//Header"):
                        key = h.find("Key").text
                        val = h.find("Value").text
                        headers[key] = val
                        if key.lower() == "content-type":
                            content_type = val.lower()
                        
                    res_headers = ''.join("%s=%s," % (k,v) for k,v in headers.iteritems()).strip(",")
                    
                    # If the attack was driven by MSI, we will find a new app installed in the control panel.
                    apps = xml.findall(".//NewApplications/Application")
                    if apps is not None:
                        for a in apps:
                            if a.text == "MITM MSI Attack":
                                attack_type = "MSI"
                                msi += 1
                    
                    # Otherwise we assume it was an exe
                    if attack_type is None:
                        attack_type = "EXE"
                        exe += 1                
                else:
                    outcome = "Attack unsuccessful"
                
                color = ""

                if outcome == "Attack successful":
                    color = Fore.GREEN + Style.BRIGHT
                    winsound.Beep(1000,500)
                elif outcome == "File dropped":
                    color = Fore.BLUE +Style.BRIGHT
                    winsound.Beep(1000,500)
                elif outcome == "File removed":
                    color = Fore.RED +Style.BRIGHT
                    winsound.Beep(1000,500)
               
                line = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (d,outcome,attack_type,attack_host,attack_url,req_headers,req_contents,res_headers,content_type,elevated)
                print(color + line)
                f.write(line+"\n")
                    
        print("------------------------------")
        print(Fore.BLUE + Style.BRIGHT+"Total processed jobs: %d" % count)
        print(Fore.BLUE + Style.BRIGHT+"Successful attacks: %d" % (exe+msi))
        print(Fore.BLUE + Style.BRIGHT+"MSI Attacks: %d" % msi)
        print(Fore.BLUE + Style.BRIGHT+"EXE Attacks: %d" % exe)
        print(Fore.BLUE + Style.BRIGHT+"Dropped files (not run): %d" % dropped)
        print(Fore.BLUE + Style.BRIGHT+"Removed files (not run): %d" % removed)
        print("------------------------------")
        l = sys.stdin.readline()