#!/usr/bin/env python2.7

import time
import urllib2
from urllib2 import Request, urlopen, HTTPError, URLError
import ssl
import cookielib
import syslog
import syslog_client
import os
import hashlib
import shutil
import

def getVarsFromFile(filename):
    import imp
    f = open(filename)
    global data
    data = imp.load_source('data', '', f)
    f.close()
def getconfig(filename):
    import imp
    c = open(filename)
    global config
    config = imp.load_source('config', '', c)
    c.close()
def goto(linenum):
    global line
    line = linenum
def dump_write():
    dump = open(dumpfile, 'w+')
    dump.write(html)

#Send Syslog Messeges
def syslog_urlerror():
    log.send('CEF:0|2bsecure|Deface Detector|1.0|100|OK|5|msg=' + app + ' ' + url_error + ' - ' + data.url, syslog_client.Level.INFO)
def syslog_ok():
    log.send('CEF:0|2bsecure|Deface Detector|1.0|100|OK|5|msg=' + app + ' ' + 'OK - ' + data.url, syslog_client.Level.INFO)
def syslog_changed():
    log.send('CEF:0|2bsecure|Deface Detector|1.0|100|Changed|5|msg=' + app + ' ' + 'Changed/Defaced - ' + data.url, syslog_client.Level.ALERT)
def syslog_defaced():
    log.send('CEF:0|2bsecure|Deface Detector|1.0|100|Defaced|5|msg=' + app + ' ' + 'Defaced/Down - ' + data.url, syslog_client.Level.ALERT)

#Status File Write for PHP
def status_urlerror():
    status.write( check_ts + ";" + app + ";" + url_error + "\n")
def status_code():
    status.write( check_ts + ";" + app + ";" + e.__unicode__() + "\n")
def status_ok():
    status.write( check_ts + ";" + '<a href="' + data.url + '" target="_blank">' + app + '</a>' + ";" + "OK" + "\n")
def status_changed():
    status.write( check_ts + ";" + '<a href="' + data.url + '" target="_blank">' + app + '</a>' + ";" + "Changed/Defaced" + "\n")
def status_defaced():
    status.write( check_ts + ";" + '<a href="' + data.url + '" target="_blank">' + app + '</a>' + ";" + "Defaced/Down" + "\n")

#Local Log
def log_urlerror():
    logfile = open(config.log_loc, 'a+')
    logfile.write("[" + check_ts + "]" + " " + url_error + " - " + app + "\n")
def log_ok():
    logfile = open(config.log_loc, 'a+')
    logfile.write("[" + check_ts + "]" + " OK - " + app + "\n")
def log_changed():
    logfile = open(config.log_loc, 'a+')
    logfile.write("[" + check_ts + "]" + " *** Changed/Defaced - " + app + " ***" + "\n")
def log_defaced():
    logfile = open(config.log_loc, 'a+')
    logfile.write("[" + check_ts + "]" + " *** Defaced - " + app + " ***" + "\n")

#HTTP request defenition
def status_addheaders():
    status.write( "Timestamp" + ";" + "Application Name" + ";" + "Status" + "\n")

getconfig('config.txt')

#Syslog Var
log = syslog_client.Syslog(config.syslog_remote_ip)

Names = []
for line in open(config.apps_loc, 'r').readlines():
    Names.append(line.strip())

open(config.tmp_status_loc, 'w').close()
status = open(config.tmp_status_loc, 'a+')
status_addheaders()

for app in Names:
        i = iter(Names)
        appfile = config.apps_path + app + ".dda"
        getVarsFromFile(appfile)

        user_agent = 'Mozilla/20.0.1 (Deface_Detector App)'
        headers = {'User-Agent' : user_agent, 'Accept-encoding' : 'gzip, deflate', 'Accept-Language' : 'en-US', 'Accept' : 'text/html'}

        try:
            cj = cookielib.CookieJar()
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        except HTTPError and URLError, e:
            print e.reason

        check_ts = time.strftime("%d/%m %H:%M:%S") #Check Timestamp
        request = urllib2.Request(data.url, None, headers)

        if data.chk_strings == 1:
            try:
                html = opener.open(request, timeout=4).read()
            except HTTPError, e:
                print app, "-", e
                if e.code == data.expected_code:
                    log_ok()
                    status_ok()
                    syslog_ok()
                else:
                    log_defaced()
                    status_code()
                    syslog_defaced()

            except URLError, e:
                print app, "-", e.reason
                url_error = str(e.reason)
                log_urlerror()
                status_urlerror()
                no_html = 1
            else:
                    print app,"- OK"


                    logfile = open(config.log_loc, 'a+')
                    dumpfile = config.dump_path + 'dd_' + app + '.dmp'

                    if html.find(data.s_string1) != -1:
                        if html.find(data.s_string2) != -1:
                            log_ok()
                            status_ok()
                            syslog_ok()
                        else:
                            print '2nd String Not Found'
                            log_changed()
                            status_changed()
                            syslog_changed()
                            dump_write()
                    else:
                        if html.find(data.s_string2) != -1:
                            print '1st String Not Found'
                            log_changed()
                            status_changed()
                            syslog_changed()
                            dump_write()
                        else:
                            log_defaced()
                            status_defaced()
                            syslog_defaced()
                            dump_write()
        if data.chk_hash == 1:
            if data.hash == 'hash':
                newhash = hashlib.md5(html).hexdigest()
                appfile.replace("hash='hash'", newhash)
                print newhash
            else:
                app_hash = hashlib.md5(html).hexdigest()
                if app_hash == data.hash:
                    log_ok()
                    status_ok()
                    syslog_ok()
                    print app + ' - Hash Is OK'
                else:
                    log_changed()
                    status_changed()
                    syslog_changed()
                    dump_write()
                    print app + ' - ' + app_hash + ' - Not Same Hash'

        if (data.chk_strings != 0 and data.chk_hash != 0):
            print 'No Checks on - ' + app #configure this later

#Copy To Production Status File
shutil.move(config.tmp_status_loc, config.prd_status_loc)
