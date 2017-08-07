import sys, random, subprocess, time, base64

# Port scans a single IP Address for vulnerabilities and prints a report in csv format
# Example: python scanIP.py ipAddress

# NEED TO DEFINE SCAN ENGINES ON NEXPOSE BEFORE SCANNING IPs
# CDK used lookup tables w/ engine IDs based on IP ranges
engine = 1

# Login Credentials
username = ""
password = ""

# Example: https://111.11.1.11:3780/api/1.1/xml
domain = ""

# Used to generate random names for site creation
def randomID(length):
    number = '0123456789'
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    id = ""
    for i in range(0,length,2):
        id += random.choice(number)
        id += random.choice(alpha)
    return id

# Runs a curl command using subprocess
def runCurl(string):
        p = subprocess.Popen(string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        response = p.stdout.read()
        return response

# Creates temporary site with specified ip
def createSite():
        curl = "curl -s -k -X POST -H \'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"utf-8\"?><SiteSaveRequest sync-id=\"123\" session-id=\"" + sessionID + "\"><Site id=\"-1\" name=\"" + name + "\" description=\"\" riskfactor=\"1.0\" isDynamic=\"0\"><Description></Description><Hosts><range from=\"" + ip + "\"/></Hosts><Credentials></Credentials><Alerting></Alerting><ScanConfig configID=\"2\" name=\"Safe network audit\" templateID=\"network-audit\" engineID=\"" + engine + "\" configVersion=\"3\"><Schedules></Schedules></ScanConfig></Site></SiteSaveRequest>\'" + domain + " | tr \' \' \"\\n\" | grep \"site-id\" | cut -f2 -d\'\"\' "
        return runCurl(curl).rstrip()

# Runs a scan on specified site
def runScan():
        curl = "curl -s -k -X POST -H \'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"utf-8\"?><SiteScanRequest sync-id=\"123\" session-id=\"" + sessionID + "\" site-id=\"" + siteID + "\"/>\' " + domain + " | tr \' \' \"\\n\" | grep \"scan-id\" | cut -f2 -d\'\"\' "
        return runCurl(curl).rstrip()

# Prints the simple results of the scan
def getResults():
        curl = "curl -s -k -X POST -H \'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"utf-8\"?><ScanStatisticsRequest sync-id=\"123\" session-id=\"" + sessionID + "\" engine-id=\"" + engine + "\" scan-id=\"" + scanID + "\"/>\' " + domain
        print runCurl(curl)

# Obtains vulnerable-exploited and vulnerable-version scan results in csv format
def getReport():
        curl = "curl -s -k -X POST -H \'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"utf-8\"?><ReportAdhocGenerateRequest session-id=\"" + sessionID + "\"><AdhocReportConfig template-id=\"basic-vulnerability-check-results\" format=\"csv\"><Filters><filter type=\"site\" id=\"" + siteID + "\"/><filter type=\"vuln-status\" id=\"vulnerable-exploited\"/><filter type=\"vuln-status\" id=\"vulnerable-version\"/></Filters></AdhocReportConfig></ReportAdhocGenerateRequest>\' " + domain
        results = str(runCurl(curl).rstrip())

        # Parses out the header response
        i = 0
        newString=""
        for char in results:
                if (i >= 8):
                        newString += char
                elif (char == '\n'):
                        i+= 1

        # Parses out the bottom lines of the curl response
        newNewString = ''
        for char in newString:
                if (char == '-'):
                        return newNewString.rstrip()
                else:
                        newNewString += char

# Deletes the temporary site
def deleteSite():
        curl = "curl -s -k -X POST -H \'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"utf-8\"?><SiteDeleteRequest sync-id=\"123\" session-id=\"" + sessionID + "\" site-id=\"" + siteID + "\"/>\' " + domain
        runCurl(curl)

# Logs in and grabs session id
login_curl = "curl -i -s -k  -X $\'POST\' -H $\'Content-Type: text/xml\' -d \'<?xml version=\"1.0\" encoding=\"UTF-8\"?><LoginRequest password=\"" + password + "\" sync-id=\"0\" user-id=\"" + username + "\"/>\' " + domain  + " | tr \' \' \"\\n\" | grep \"session-id\" | cut -f2 -d\'\"\' "
sessionID = runCurl(login_curl).rstrip()

ip = sys.argv[1]
name = randomID(10)
time.sleep(3)

if (engine != "NA"):
        siteID = createSite()
        time.sleep(3)
        scanID = runScan()
        time.sleep(250)
        print base64.b64decode(getReport()).rstrip()
        time.sleep(10)
        deleteSite()
