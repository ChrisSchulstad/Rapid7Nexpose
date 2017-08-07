import csv
import subprocess
import time

# Defines IP ranges in Nexpose from a CSV file

# Login Credentials
username = ""
password = ""

# Example: https://111.11.1.11:3780/api/1.1/xml
domain = ""

# Define the CSV
f = open('test.csv')
file = csv.reader(f)

# Uses subprocess to run a curl
def runCurl(myString):
        p = subprocess.Popen(myString, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = p.stdout.read()
        return output

# Creates a site with specified ips and scan engine
def createSite(ip, engine, name):

        # Parses the specified IP in xml for Nexpose API
        parsedIP = ""
        for char in ip:
                if (char == '-'):
                        parsedIP += "\" to=\""
                elif (char == ','):
                        parsedIP += "\"/><range from=\""
                elif (char != ' '):
                        parsedIP += char

        create_curl = "curl -s -k -X POST -H \'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"utf-8\"?><SiteSaveRequest sync-id=\"123\" session-id=\"" + sessionID + "\"><Site id=\"-1\" name=\"" + name + "\" description=\"\" riskfactor=\"1.0\" isDynamic=\"0\"><Description></Description><Hosts><range from=\"" + parsedIP + "\"/></Hosts><Credentials></Credentials><Alerting></Alerting><ScanConfig configID=\"2\" name=\"Safe network audit\" templateID=\"network-audit\" engineID=\"" + engine + "\" configVersion=\"3\"><Schedules></Schedules></ScanConfig></Site></SiteSaveRequest>\'" + domain
        print runCurl(create_curl)

# Logs in and grabs session id
login_curl = "curl -i -s -k  -X $\'POST\' -H $\'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"UTF-8\"?><LoginRequest password=\"" + password + "\" sync-id=\"0\" user-id=\"" + username + "\"/>\' " + domain + " | tr \' \' \"\\n\" | grep \"session-id\" | cut -f2 -d\'\"\' "
sessionID = runCurl(login_curl)[:-1]
print "Connection successful. SessionID = " + sessionID

# Automated scanning of ips specified in 'nexpose.csv'
for row in file:
        createSite(ip=row[1], engine=row[2], name=row[0])
        time.sleep(3)

print "Sites Created"
