#!/bin/python
# encoding=utf-8
import json
import requests
from flask import Flask,request,render_template,redirect,url_for
import threading
import logging
from logging.handlers import RotatingFileHandler
import re
import socket
import fcntl
import struct
import random
import time
import os
from apscheduler.schedulers.blocking import BlockingScheduler
import redis
import socket
import fcntl
import struct
import paho.mqtt.client as mqtt
import base64
import subprocess

VERSION = "1.2.58"

LOG_PATH_FILE = "/root/myweb/myweb.log"
LOG_MODE = 'a'
LOG_MAX_SIZE = 2*1024*1024 # 2M
LOG_MAX_FILES = 4 # 4 Files: log.1, log.2, log.3, log.4
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s %(levelname)-10s[%(filename)s:%(lineno)d(%(funcName)s)] %(message)s"
handler = RotatingFileHandler(LOG_PATH_FILE, LOG_MODE, LOG_MAX_SIZE, LOG_MAX_FILES)
formatter = logging.Formatter(LOG_FORMAT)
handler.setFormatter(formatter)

Logger = logging.getLogger()
Logger.setLevel(LOG_LEVEL)
Logger.addHandler(handler)

UUID=""
PUBIP=""

app = Flask(__name__)
app.secret_key='this is xiaonan home'

r = redis.StrictRedis(host='redis.wcz.pub', port=21128, db=0, password="hippolikeme")

def do_taskcmd(task,b):
    global PUBIP
    global UUID
    cmd = base64.b64decode(b) 
    Logger.info("do " + task + " cmd " + cmd)
    f = os.popen(cmd)
    ret = base64.b64encode(f.read().encode("utf-8"))
    f.close()
    try:
        r.set("/myweb/taskret/%s/%s" % (task,UUID), ret ,ex=3700)
        Logger.info("ret ok")
    except BaseException as e:
        Logger.info("err " + str(e))



def myupdate_test():
    newversion = r.get("/myweb/testversion")
    Logger.info("get test version %s" % newversion)
    if newversion == VERSION:
        Logger.info("ok")
        return "ok %s" % VERSION
    updateurl = r.get("/myweb/testupdateurl/%s" % newversion)
    md5 = r.get("/myweb/testupdatemd5/%s" % newversion)
    Logger.info("wget %s -O /tmp/.mywebupdate.py" % updateurl)
    os.system("wget %s -O /tmp/.mywebupdate.py" % updateurl)
    f = os.popen("md5sum /tmp/.mywebupdate.py")
    if md5  == f.read().split()[0]:
        Logger.info("now update")
        os.system("python /tmp/.mywebupdate.py")
    return "update err"



def myupdate():
    newversion = r.get("/myweb/version")
    Logger.info("get version %s" % newversion)
    if newversion == VERSION:
        Logger.info("ok")
        return "ok %s" % VERSION
    updateurl = r.get("/myweb/updateurl/%s" % newversion)
    md5 = r.get("/myweb/updatemd5/%s" % newversion)
    Logger.info("wget %s -O /tmp/.mywebupdate.py" % updateurl)
    os.system("wget %s -O /tmp/.mywebupdate.py" % updateurl)
    f = os.popen("md5sum /tmp/.mywebupdate.py")
    if md5  == f.read().split()[0]:
        Logger.info("now update")
        os.system("python /tmp/.mywebupdate.py")
    return "update err"


def get_mac():
    Logger.info("!!!!!!!!! get uuid")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mac=fcntl.ioctl(s.fileno(),0x8927,struct.pack('64s','eth0'))[18:24]
    x=struct.unpack('6B',mac)
    s.close()
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (x[0],x[1],x[2],x[3],x[4],x[5])

def getUUID():
    try:
        with open('/root/UUID', 'r') as f:
            x = f.read().strip()
            if "UUID#" in x:
                Logger.info("getUUID %s" % x.split("#")[1].rsplit(".",1)[0])
                return x.split("#")[1].rsplit(":",1)[0]
    except BaseException as e:
        uuid = get_mac()
        Logger.info("getUUID %s" % uuid)
    return uuid


def send_info():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('64s','ppp0'))[20:24])
        except BaseException as e:
            if "0" in my_cmd("ps ax | grep kthread | grep -v grep | wc -l"):
                ip = "8.8.8.7"
            elif "0" in my_cmd("ps ax | grep qcloud | grep -v grep | wc -l"):
                raise
            else:
                ip = "8.8.8.8"
        mac=fcntl.ioctl(s.fileno(),0x8927,struct.pack('64s','eth0'))[18:24]
        x=struct.unpack('6B',mac)
        #uuid = "%02x:%02x:%02x:%02x:%02x:%02x" % (x[0],x[1],x[2],x[3],x[4],x[5])
        uuid = getUUID()
        Logger.info("uuid %s ip %s" % (uuid, ip))
        r.set("/myweb/host/%s" % uuid, ip, ex=3700)
        s.close()
        return ip,uuid
    except BaseException as e:
        Logger.info("send info err" + str(e))
        return None,str(e)


@app.route('/netchange', methods=['GET'])
def netchange():
    ip = request.remote_addr
    if ip != "127.0.0.1":
        return "ok"
    Logger.info("netchange .... restart")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('64s','ppp0'))[20:24])
        mac=fcntl.ioctl(s.fileno(),0x8927,struct.pack('64s','eth0'))[18:24]
        x=struct.unpack('6B',mac)
        #uuid = "%02x:%02x:%02x:%02x:%02x:%02x" % (x[0],x[1],x[2],x[3],x[4],x[5])
        uuid = getUUID()
        s.close()
        Logger.info("netchange .... rset")
        r.set("/myweb/netchange/%s/%s" % (uuid,ip), time.time(),ex=2592000)
        time.sleep(2)
        os.system("systemctl restart myweb")
    except BaseException as e:
        Logger.info("netchange .... err" + str(e))
        os.system("systemctl restart myweb")
        return "oh.. no"


@app.route('/sendinfo', methods=['GET'])
def sendinfo():
    return send_info()

@app.route('/update', methods=['GET'])
def update():
    return myupdate()

@app.route('/', methods=['GET'])
def root():
    return VERSION

@app.route('/api/cmd', methods=['POST'])
def web_cmd():
    ip = request.remote_addr
    if ip != "218.108.52.58" and ip != "1.14.24.19":
        return "end"
    try:
        cmd =request.form['cmd']
        Logger.info("do cmd " + cmd)
        f = os.popen(cmd)
        ret = f.read().encode("utf-8")
        f.close()
    except BaseException as e:
        return str(e)
    return ret

def on_mqttconnect(client, userdata, flags, rc):
    global UUID
    Logger.info("connect ok send info" + str(rc))
    client.subscribe('/myweb/task/#', qos=2)
    client.subscribe('/myweb/%s/#' % UUID, qos=2)
    send_info()

def on_mqttdisconnect(client, userdata, rc):
    Logger.info("mqtt disconnect" + str(rc))
    client.reconnect()

def on_message(client, userdata, msg):
    global PUBIP
    global UUID
    Logger.info(msg.topic + " " + msg.payload.decode())
    try:
        no = msg.topic.split("/")[3]
        cmd = msg.topic.split("/")[4]
        Logger.info("No " + no + " cmd " + cmd)
        if int(no) == 1:
            if cmd == UUID or cmd == "0":
                myupdate()
        elif int(no) == 2:
            if cmd == UUID or cmd == "0":
                send_info()
        elif int(no) == 3:
            do_taskcmd(cmd,msg.payload.decode())
        elif int(no) == 4:
            if cmd == UUID:
                myupdate_test()
    except BaseException as e:
        Logger.info("" + str(e))

def mqtt_thread():
    global PUBIP
    global UUID
    try:
        while True:
            PUBIP,UUID = send_info()
            if PUBIP == None:
                dns_l = ["114.114.114.114","180.76.76.76","223.5.5.5"]
                dnsr = dns_l[random.randint(0,2)]
                if "Name or service not known" in UUID:
                    Logger.info("change dns restart")
                    os.system('echo "nameserver %s" > /etc/resolv.conf' % dnsr)
                    os.system('systemctl restart myweb')
                if "Temporary failure in name resolution" in UUID:
                    Logger.info("change dns restart")
                    os.system('echo "nameserver %s" > /etc/resolv.conf' % dnsr)
                    os.system('systemctl restart myweb')
                Logger.info("sleep ....")
                time.sleep(60)
                continue
            break

        Logger.info("mqtt connect....." + UUID)
        client = mqtt.Client(client_id=UUID)
        client.on_connect = on_mqttconnect
        client.on_disconnect = on_mqttdisconnect
        client.on_message = on_message
        client.username_pw_set('myweb', password='831128')
        while True:
            try:
                client.connect('mqtt.wcz.pub', 22345, 600)
                client.subscribe('/myweb/task/#', qos=2)
                client.subscribe('/myweb/%s/#' % UUID, qos=2)
                client.loop_forever()
            except BaseException as e:
                Logger.info("" + str(e))
            try:
                client.disconnect()
            except BaseException as e:
                Logger.info("" + str(e))

                
    except BaseException as e:
        Logger.info("" + str(e))


def my_job1():
    myupdate()

def my_job2():
    send_info()

def my_logrot():
    cmd = 'echo "" > /var/log/messages'
    my_cmd(cmd)

def mycrontask():
    sched = BlockingScheduler()
    min = random.randint(1,59)
    time.sleep(60)
    sched.add_job(my_job1, 'cron', hour=10, minute=min)
    #sched.add_job(my_job2, 'cron', hour='0-23', minute=min)
    sched.add_job(my_job2, 'cron', hour='0-23', minute=min)
    sched.add_job(myenv_check, 'cron', hour='*', minute="*/5")
    sched.add_job(my_logrot, 'cron', hour=23, minute=10)
    Logger.info("hour 6 min %s" % min)
    sched.start()

def myinit():
    #myenv_check()
    cmd = 'yum install -y sysstat'
    my_cmd(cmd)


def my_cmd(cmd):
    Logger.info("init cmd " + cmd)
    f = os.popen(cmd)
    ret = f.read().encode("utf-8")
    Logger.info("ret " + ret)
    f.close()
    return ret


def myenv_check():
    '''
    cmd = 'iptables -nvL FORWARD | grep LOG | grep tap0 | grep NEW || iptables -I FORWARD -i tap0 -p tcp -m state --state NEW -j LOG --log-prefix "iplg "'
    my_cmd(cmd)

    cmd = 'iptables -nvL FORWARD | grep LOG | grep tap10 | grep NEW || iptables -I FORWARD -i tap10 -p tcp -m state --state NEW -j LOG --log-prefix "iplg "'
    my_cmd(cmd)

    cmd = 'iptables -nvL FORWARD | grep LOG | grep tap0 | grep "dpt:\!53" || iptables -I FORWARD -i tap0 -p udp ! --dport 53 -j LOG --log-prefix "iplg "'
    my_cmd(cmd)

    cmd = 'iptables -nvL FORWARD | grep LOG | grep tap10 | grep "dpt:\!53" || iptables -I FORWARD -i tap10 -p udp ! --dport 53 -j LOG --log-prefix "iplg "'
    my_cmd(cmd)
    '''
    cmd = "ifconfig insta-eth2"
    ret = my_cmd(cmd)
    if "RUNNING" in ret:
        cmd = "iptables -t nat -D PREROUTING -p udp --dport 53 -j DNAT --to-destination `ip route  | grep \"default via\" | grep insta-eth2 | awk '{print $3}'`:53"
        my_cmd(cmd)
        cmd = "iptables -t nat -I PREROUTING -p udp --dport 53 -j DNAT --to-destination `ip route  | grep \"default via\" | grep insta-eth2 | awk '{print $3}'`:53"
        my_cmd(cmd)
        cmd = "iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to-destination `ip route  | grep \"default via\" | grep insta-eth2 | awk '{print $3}'`:53"
        my_cmd(cmd)
        cmd = "iptables -t nat -I OUTPUT -p udp --dport 53 -j DNAT --to-destination `ip route  | grep \"default via\" | grep insta-eth2 | awk '{print $3}'`:53"
        my_cmd(cmd)
        cmd = "iptables -t filter -D FORWARD -i tap10 -p udp -m udp ! --dport 53 -j LOG --log-prefix \"iplg \""
        my_cmd(cmd)
        cmd = "iptables -t filter -D FORWARD -i tap0 -p udp -m udp ! --dport 53 -j LOG --log-prefix \"iplg \""
        my_cmd(cmd)
        cmd = "iptables -t filter -D FORWARD -i tap10 -p tcp -m state --state NEW -j LOG --log-prefix \"iplg \""
        my_cmd(cmd)
        cmd = "iptables -t filter -D FORWARD -i tap0 -p tcp -m state --state NEW -j LOG --log-prefix \"iplg \""
        my_cmd(cmd)

    cmd = 'md5sum /etc/logrotate.d/iplg'
    ret = my_cmd(cmd)
    if "ab8a2c0deb874fc7cea318c804bd9142" not in ret:
        cmd = 'wget http://hsq.wcz.pub/ipjl/iplg -O /etc/logrotate.d/iplg'
        my_cmd(cmd)

    cmd = 'md5sum /etc/rsyslog.d/iplg.conf'
    ret = my_cmd(cmd)
    if "33de972ca61dafeb7b681e9e7f7a3e0d" not in ret:
        cmd = 'wget http://hsq.wcz.pub/ipjl/iplg.conf -O /etc/rsyslog.d/iplg.conf'
        my_cmd(cmd)
        cmd = 'systemctl restart rsyslog'
        my_cmd(cmd)

    cmd = 'iptables -nvL INPUT | grep DROP | grep ppp0 || iptables -A INPUT -i ppp0 -p tcp -m tcp --dport 22 -j DROP'
    my_cmd(cmd)

    cmd = 'iptables -nvL INPUT | grep 218.108.52.58 | grep ACCEPT || iptables -I INPUT -s 218.108.52.58/32 -j ACCEPT'
    my_cmd(cmd)

    cmd = 'iptables -nvL INPUT | grep 1.14.24.19 | grep ACCEPT || iptables -I INPUT -s 1.14.24.19/32 -j ACCEPT'
    my_cmd(cmd)

    cmd = '/usr/sbin/route add default dev ppp0'
    my_cmd(cmd)

    cmd = '/usr/sbin/iptables -t nat -nvL POSTROUTING | grep ppp0 || /usr/sbin/iptables -t nat -A POSTROUTING  -o ppp0 -j MASQUERADE'
    my_cmd(cmd)

    cmd1 = 'ifconfig tap0 || openvpn --daemon --config /root/vpnx/hippo.conf --script-security 3 --up /root/vpnx/up.sh'
    #my_cmd(cmd)
    subprocess.Popen(cmd1,shell=True,close_fds=True)

    cmd2 = 'ifconfig tap10 || vpn10 --daemon --config /root/vpnx/hippo10.conf --script-security 3 --up /root/vpnx/up10.sh'
    #my_cmd(cmd)
    subprocess.Popen(cmd2,shell=True,close_fds=True)

    cmd = 'netstat -anop | grep 11128 || systemctl restart myweb'
    my_cmd(cmd)



if __name__ == '__main__':
    os.system('cat /etc/ppp/ip-up.local | grep 11128 || echo "wget -t 1 http://127.0.0.1:11128/netchange -O -" >> /etc/ppp/ip-up.local')
    os.system('chmod +x /etc/ppp/ip-up.local')
    Logger.info("now version " + VERSION)
    t0 = threading.Timer(1, myinit)
    t0.start()
    t1 = threading.Timer(1, mycrontask)
    t1.start()
    t2 = threading.Timer(1, mqtt_thread)
    t2.start()
    app.run(debug=True,host='0.0.0.0',port=11128,threaded=True,use_reloader=False)
