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
import select
import requests.packages.urllib3.util.connection as urllib3_cn
import subprocess

LOG_PATH_FILE = "/root/ipjl/ipjl.log"
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

VERSION = "1.2.31"


sched = BlockingScheduler()

app = Flask(__name__)
app.secret_key='this is xiaonan home'

f = os.popen(r"cat /root/vpnx/hippo.conf  | grep -v '#' | grep lladdr | cut -d ':' -f 4")
NET=int(f.readlines()[0].split()[0],16)
#print NET,"%d"% NET

f = os.popen(r"cat /root/vpnx/hippo10.conf  | grep -v '#' | grep lladdr | cut -d ':' -f 4")
NET10=int(f.readlines()[0].split()[0],16)
#print NET10,"%d"% NET10

f = os.popen(r"cat /root/vpnx/hippo20.conf  | grep -v '#' | grep lladdr | cut -d ':' -f 4")
NET20=int(f.readlines()[0].split()[0],16)
#print NET10,"%d"% NET10


#Senderr = False


SEND_FILE = '/root/checklog_ok'

def setok():
	with open(SEND_FILE,mode='w') as f:
		f.write("ok")

def checkok():
	if os.path.exists(SEND_FILE):
		os.remove(SEND_FILE)
		return True
	return False

def get_mac():
	Logger.info("!!!!!!!!! get uuid")
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	mac=fcntl.ioctl(s.fileno(),0x8927,struct.pack('64s','eth0'))[18:24]
	#mac=fcntl.ioctl(s.fileno(),0x8927,struct.pack('64s','ens192'))[18:24]
	x=struct.unpack('6B',mac)
	s.close()
	return "%02x:%02x:%02x:%02x:%02x:%02x" % (x[0],x[1],x[2],x[3],x[4],x[5])

def getUUID():
	try:
		with open('/root/UUID', 'r') as f:
			x = f.read().strip()
			if "UUID#" in x:
				Logger.info("getUUID %s" % x.split("#")[1])
				return x.split("#")[1]
	except BaseException as e:
		Logger.info("getUUID err %s" % e)
	uuid = "%s:%02x" % (get_mac(),random.randint(0,250))
	fd=open('/root/UUID','w')
	name = fd.write("UUID#%s" % uuid)
	fd.close()
	Logger.info("getUUID %s" % uuid)
	return uuid
 


def getName():
	try:
		fd=open('/root/NAME','r')
		name = fd.read().strip()
		fd.close()
		return name
	except BaseException as e:
		Logger.info("getName %s" % e)
		return "Unkown"

def getFrom():
	try:
		fd=open('/root/FROM','r')
		name = fd.read().strip()
		fd.close()
		return name
	except BaseException as e:
		Logger.info("getFrom %s" % e)
		return "Unkown"


def getCity():
	global G_CITY
	global G_PRO
	try:
		with open('/root/city_pro', 'r') as f:
			x = f.read().strip()
			if "city#" in x:
				G_CITY= x.split("#")[1]
				G_PRO= x.split("#")[2]
				Logger.info("getcity %s" % G_CITY)
				Logger.info("getpro %s" % G_PRO)
				return
	except BaseException as e:
		Logger.info("getUUID err %s" % e)
	try:
		res=requests.get("http://myip.ipip.net", timeout=10)
		if res.status_code == 200:
			G_CITY = res.text.split()[4]
			G_PRO = res.text.split()[3]
	                fd=open('/root/city_pro','w')
                        out = "city#%s#%s" % (G_CITY,G_PRO)
	                name = fd.write(out.encode('utf-8'))
	                fd.close()
			Logger.info("getCity %s ", out)
			return
	except BaseException as e:
		Logger.info(e)
		pass


def jikeIP():
    global G_IP
    f = os.popen(r"ifconfig | grep insta-eth")
    xx = f.readlines()
    if len(xx) == 0:
        Logger.info("not jike ip")
        return
    try:
        f = os.popen(r"curl myip.ipip.net --interface eth0")
        xx = f.readlines()
        G_IP = xx[0].split("：")[1].split()[0]
        Logger.info("getjikeIP %s" % G_IP)
        if "127.0.0." not in G_IP:
            return
    except BaseException as e:
        Logger.info(e)
        pass

    f = os.popen(r"curl cip.cc --interface eth0")
    xx = f.readlines()
    G_IP = xx[0].split(":")[1].split()[0]
    Logger.info("getjikeIP %s" % G_IP)
    return



def allowed_gai_family():
    """
     https://github.com/shazow/urllib3/blob/master/urllib3/util/connection.py
    """
    family = socket.AF_INET
    return family



def getIP():
	global G_IP
	urllib3_cn.allowed_gai_family = allowed_gai_family
	try:
		try:
			res=requests.get("http://myip.ipip.net", timeout=10)
			if res.status_code == 200:
				G_IP = res.text.split()[1].split(u"：")[1]
				Logger.info("getPubIP %s" % G_IP)
				if "127.0.0." not in G_IP:
					return
		except BaseException as e:
			Logger.info(e)
			pass
		'''
		res=requests.get("http://pv.sohu.com/cityjson", timeout=10)
		if res.status_code == 200:
			#print(re.split("{|}",res.text)[1])
			out = json.loads("{"+re.split("{|}",res.text)[1]+"}")
			G_IP = out['cip']
			Logger.info("getPubIP2 %s " % G_IP)
			return
		'''
		res=requests.get("http://ip.wcz.pub", timeout=10)
		if res.status_code == 200:
			G_IP = res.text.split()[0]
			Logger.info("getPubIP2 %s " % G_IP)
			return
	except BaseException as e:
		Logger.info(e)
		G_IP = "8.8.8.8"
		return

G_UUID = getUUID()
G_NAME = getName()
G_FROM = getFrom()
G_CITY = u'未知'
G_PRO = u'未知'
getCity()
G_IP = "8.8.8.8"
#getIP()

timelist=[]


def savev2ray(name,mail):
	r = redis.StrictRedis(host='localhost', port=6379, db=0)
	r.set("v2ray_name/%s" % name, mail, ex=3600*48)
	r.close()

def delv2ray(name,mail):
	r = redis.StrictRedis(host='localhost', port=6379, db=0)
	r.delete("v2ray_name/%s" % name, mail)
	r.close()

def loadv2ray():
	r = redis.StrictRedis(host='localhost', port=6379, db=0)
	for x in r.keys("v2ray_name/*"):
		Logger.info("/root/ipjl/v2test %s %s" % (x[11:], r.get(x)))
		os.system("/root/ipjl/v2test %s %s" % (x[11:], r.get(x)))
	r.close()


def upIP():
	global G_IP
	r = redis.StrictRedis(host='localhost', port=6379, db=0)
	r.sadd("pubip", G_IP)
	r.close()



def send_heart_one():
	global G_IP
	global G_UUID
	global G_NAME
	global G_CITY
	global G_PRO
	global G_FROM
	try:
		getIP()
		if G_IP == "8.8.8.8":
			raise
		Logger.info("getIP ok.")
		upIP()
                jikeIP()
	except:
		Logger.info("getIP err..")
		return 1
	url='https://hmjl.longene.com.cn/proxy/heartbeat'
	#url='http://ipjltest.longene.com.cn/proxy/heartbeat'
	#url='http://10.3.10.99/proxy/heartbeat'
	headers={
		'content-type':'application/x-www-form-urlencoded',
		'token':'56a75641-dee8-44e4-ac25-9282fa3536da'
	}
	data={
		"name":G_NAME,
		"chunnelStatus": 1,
		"uuid":G_UUID,
		"publicIp": G_IP,
		"vpnIp": "128.0.0.1",
		"connectNum": 99,
		"ipSource": G_FROM,
		"city": G_CITY, 
		"pro": G_PRO, 
		"version": VERSION, 
	}
	Logger.info(json.dumps(data))
	res=requests.post(url,data,headers=headers,timeout=30)
	Logger.info("send ok..........")
	try:
		for myjob in sched.get_jobs():
			Logger.info("name " + myjob.name + " next_run_time " + str(myjob.next_run_time) + " " + str(myjob.pending) + " " + str(myjob.trigger))
		Logger.info(sched.running)
	except:
		Logger.info("job err..............")
	#return (res.json())
	return 0


def check_env():
	Logger.info("check .......")
	#os.system("echo 'wget http://127.0.0.1:7008/resend -O -' > /etc/ppp/ip-up.local")
	os.system('cat /etc/ppp/ip-up.local | grep 7008 || echo "wget http://127.0.0.1:7008/resend -O -" >> /etc/ppp/ip-up.local')
	os.system("chmod +x /etc/ppp/ip-up.local")
	Logger.info("check ....... ok ")



def send_heart_all():
    global G_IP
    while True:
        tt = 300
        Logger.info("go 1")
        try:
            ret = send_heart_one()
        except:
            tt = 10
        if G_IP == "8.8.8.8":
            tt = 10
        if ret == 1:
            tt = 10
        check_env()
        Logger.info("sleep 1")
        time.sleep(tt)
        Logger.info("sleep 2..............")

def send_heart():
	send_heart_one()
	check_env()
	t = threading.Timer(3, send_heart_all)
	t.start()
	Logger.info("go 100000")
	return


@app.route('/dynamicSwitch/', methods=['POST'])
def dynamicSwitch():
	try:
		appkey = request.form.get("appkey")
		ison = int(request.form.get("isOn"))
		assert(appkey)
	except:
		data={
			"success":False,
			"code": "arg err",
			"message": "ok",
		}
		return json.dumps(data)

	Logger.info("dynamicSwitch %s %d" % (appkey, ison))
	if ison == 1:
		os.system("echo '%s' > /root/vpnx/uuid" % appkey)
	else:
		os.system("rm -rf /root/vpnx/uuid")
	data={
		"success":True,
		"code": "ok",
		"message": "ok",
	}
	return json.dumps(data)


@app.route('/resend', methods=['GET'])
def resend():
	t1 = threading.Timer(2, send_heart_one)
	t1.start()
	Logger.info("resend")
	return "ok"

@app.route('/reboot/', methods=['POST'])
def reboot():
	Logger.info("get Reboot")
	print("ok")
	data={
		"success":True,
		"code": "ok",
		"message": "ok",
	}
	return json.dumps(data)

@app.route('/sendUserInfo/', methods=['POST'])
def sendUserInfo():
	try:
		vpnid = request.form.get("vpnId")
		email = request.form.get("phone")
		assert(vpnid)
		assert(email)
	except:
		data={
			"success":False,
			"code": "arg err",
			"message": "ok",
		}
		return json.dumps(data)

	Logger.info("/root/ipjl/v2test %s %s" % (vpnid, email))
	savev2ray(vpnid, email)
	os.system("/root/ipjl/v2test %s %s" % (vpnid, email))
	data={
		"success":True,
		"code": "ok",
		"message": "ok",
	}
	return json.dumps(data)



def stopvpn(ip,appkey):
	try:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		fcntl.fcntl(s.fileno(),fcntl.F_SETFD, fcntl.FD_CLOEXEC)
		s.settimeout(3)
		err=s.connect_ex((ip, 12345))
		info = "cmd=1711\tappkey=%s\t\r\n" % appkey
		pad = struct.pack("H",1800)
		pad += struct.pack("I",len(info))
		pad += info
		ret = s.send(pad)
		Logger.info("stop vpn....%s %s"(ip,appkey))
		s.close()
	except Exception as e:
		print "Except ",str(e)

@app.route('/stopProxy/', methods=['POST'])
def stopProxy():
	Logger.info("get stopProxy.....")
	try:
		vpnid = request.form.get("vpnId")
		email = request.form.get("phone")
		assert(vpnid)
		assert(email)
	except:
		try:
			ip = request.form.get("deviceIpNat")
			appkey = request.form.get("appkey")
			stopvpn(ip,appkey)
			data={
				"success":True,
				"code": "ok",
				"message": "ok",
			}
		except:
			data={
				"success":False,
				"code": "arg err",
				"message": "ok",
			}
		return json.dumps(data)

	Logger.info("/root/ipjl/v2del %s %s" % (vpnid, email))
	os.system("/root/ipjl/v2del %s %s" % (vpnid, email))
	delv2ray(vpnid, email)
	data={
		"success":True,
		"code": "ok",
		"message": "ok",
	}
	return json.dumps(data)


def do_speedLimit(limit_l):
	try:
		tc_limit={}
		ip_list=[]
		os.system(r"tc qdisc del dev tap0 root");
		os.system(r"tc qdisc add dev tap0 root handle 1: htb default 10");
		os.system(r"tc class add dev tap0 parent 1: classid 1:10 htb rate 100000kbit  prio 1");

		os.system(r"tc qdisc del dev tap10 root");
		os.system(r"tc qdisc add dev tap10 root handle 1: htb default 10");
		os.system(r"tc class add dev tap10 parent 1: classid 1:10 htb rate 100000kbit  prio 1");

		os.system(r"tc qdisc del dev tap20 root");
		os.system(r"tc qdisc add dev tap20 root handle 1: htb default 10");
		os.system(r"tc class add dev tap20 parent 1: classid 1:10 htb rate 100000kbit  prio 1");

		tc_num=20
		for i in limit_l:
			ip_list.append(i['deviceIp'])
			if i['speed'] != '0': 
				x=i['deviceIp']
				Logger.info(r"tc class add dev tap0 parent 1: classid 1:%d htb rate %skbit  prio 10" %(tc_num,i['speed']));
				os.system(r"tc class add dev tap0 parent 1: classid 1:%d htb rate %skbit  prio 10" %(tc_num,i['speed']));
				Logger.info(r"tc filter add dev tap0 parent 1: protocol ip prio 30 u32 match ip dst %s flowid 1:%d" % (x,tc_num));
				os.system(r"tc filter add dev tap0 parent 1: protocol ip prio 30 u32 match ip dst %s flowid 1:%d" % (x,tc_num));
				tc_num+=1

		cmd="iptables -nvL ARM_LIULIANG | grep -v"
		for ip in ip_list:
			Logger.info(r"iptables -nvL ARM_LIULIANG | grep %s || iptables -A ARM_LIULIANG -d %s/32 -j ACCEPT"%(ip,ip))
			os.system(r"iptables -nvL ARM_LIULIANG | grep %s || iptables -A ARM_LIULIANG -d %s/32 -j ACCEPT"%(ip,ip))
			cmd=cmd+" -e %s" % ip
		cmd=cmd+" | grep ACCEPT | awk '{system(\"iptables -D ARM_LIULIANG -d \"$9\"/32 -j ACCEPT\")}'"
		Logger.info("cmd " + cmd)
		os.system(cmd)
	except Exception as e:
		Logger.info("cmd103 Except %s" % str(e))

@app.route('/speedLimit/', methods=['POST'])
def speedLimit():
	Logger.info("get speedLimit.....")
	try:
		list = request.form.get("list")
		limit_l = json.loads(list)
		Logger.info(limit_l)
		do_speedLimit(limit_l)
	except:
		data={
			"success":False,
			"code": "arg err",
			"message": "arg err",
		}
		return json.dumps(data)

	data={
		"success":True,
		"code": "ok",
		"message": "ok",
	}
	return json.dumps(data)


@app.route('/getNetInfo/', methods=['POST'])
def getNetInfo():
	Logger.info("get NetInfo.....")
	try:
		ret = my_cmd("sar -n DEV 3 1")
		go = 0
		avg = ""
		for x in ret.split("\n"):
			if "IFACE" in x:
				go += 1
				continue
			if go == 1:
				xx = x.split()
				if(len(xx) > 6):
					avg += ""+xx[0]+" "+xx[1]+" rx "+xx[4]+" tx "+xx[5]
	except:
		data={
			"success":False,
			"code": "arg err",
			"message": "arg err",
			"data":{
				"averageBandwidth":"err"
			}
		}
		Logger.info("get NetInfo.....err")
		return json.dumps(data)

	data={
		"success":True,
		"code": "ok",
		"message": "ok",
		"data":{
			"averageBandwidth":avg
		}
	}
	Logger.info("get NetInfo....." + avg)
	return json.dumps(data)



def my_job3():
    os.system("systemctl restart v2ray")

def my_job5():
    os.system("ntpdate cn.pool.ntp.org")

def my_job4():
	#global Senderr
	global G_UUID
	if checkok() != True:
		headers={
			'content-type':'application/json',
		}
		data={
			"msgtype": "text","text": {"content":"rizhi %s" % G_UUID}
		}
		url = "https://oapi.dingtalk.com/robot/send?access_token=120f4938782b231021100aa8d399e764fddce4d24d066735faa32e1cbccf4673"
		res=requests.post(url,json=data,headers=headers,timeout=30)

def my_job2():
    flist = os.listdir("/tmp/")
    for x in flist:
        try:
            file_name = os.path.join("/tmp/", x)
            if os.path.isfile(file_name):
                if "ipr_" in x[0:4]:
                    Logger.info("send %s" % file_name)
                    files = {'files': open(file_name, 'rb')}
                    res = requests.post(url="https://hmjl.longene.com.cn/proxy/uploadLogFile/", files=files, timeout=300)
                    #res = requests.post(url="http://ipjltest.longene.com.cn/proxy/uploadLogFile/", files=files )
                    if res.json()['success']:
                        Logger.info("delfile %s" % file_name)
                        os.remove(file_name)
        except:
            continue


def my_job1():
        global G_UUID
        #global Senderr
        #Senderr = True
        checkok()
        Logger.info("job1 start")
        r = redis.StrictRedis(host='localhost', port=6379, db=0)
        cmd = 'rm -rf `ls  /var/log/iplg*gz | awk -F \'.\' \'{print $1"."$2}\'`'
        my_cmd(cmd)
        Logger.info("clean log ok....")

        cmd = 'logrotate -f /etc/logrotate.d/iplg'
        my_cmd(cmd)
        Logger.info("logrotate ok....")

        cmd = 'systemctl restart log0'
        my_cmd(cmd)
        Logger.info("restart log0 ok....")

        cmd = 'systemctl restart log10'
        my_cmd(cmd)
        Logger.info("restart log10 ok....")

        file_name1 = "/var/log/iplg.log-%s" % time.strftime('%Y%m%d', time.localtime(time.time()))
        Logger.info("job1 read file %s" % file_name1)
        os.system("cat %s | awk '{print $10\" \"$11}' | sort -u > /tmp/.iptt" % file_name1)
        try:
            f1 = open("/tmp/.iptt", "r")
            for x in f1.readlines():
                try:
                        src = x.split()[0].split("=")[1]
                        dst = x.split()[1].split("=")[1]
                        #print(src,dst)
                        r.sadd("v2log/%s" % src, dst)
                except:
                        pass
            f1.close()
        except:
                Logger.info("f1 err")
                pass
        Logger.info("iptt ok")

        file_name = "/tmp/ipr_%s_%s" % (G_UUID,time.strftime('%Y-%m-%d_%H:%M:%S', time.localtime(time.time())))
        f = open(file_name, "w")
        f.write("pubip----\n")
        y = r.spop("pubip")
        while y != None:
                f.write(y)
                f.write("\n")
                y = r.spop("pubip")
        for x in r.keys('v2log/*'):
		f.write("user=" + x[6:])
                f.write("\n")
                y = r.spop(x)
                while y != None:
                        f.write(y)
                        f.write("\n")
                        y = r.spop(x)
        Logger.info("#######job1 file ok")
        #Senderr = False
        setok()
        r.close()
        f.close()

def my_cmd(cmd):
    Logger.info("init cmd " + cmd)
    f = os.popen(cmd)
    #ret = f.read().encode("utf-8")
    ret = f.read()
    Logger.info("ret " + ret)
    f.close()
    return ret



def get_tapip():
	out= '{'
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('64s','tap0'))[20:24])
		s.close()
		if out[-1] == '{':
			out+= '"xx":"'+ip+'"'
		else:
			out+= ',"xx":"'+ip+'"'
	except Exception as e:
		Logger.info("%s" % str(e))
		start_vpn()

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('64s','tap10'))[20:24])
		s.close()
		if out[-1] == '{':
			out+= '"jh":"'+ip+'"'
		else:
			out+= ',"jh":"'+ip+'"'
	except Exception as e:
		Logger.info("%s" % str(e))
		start_vpn10()

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('64s','tap20'))[20:24])
		s.close()
		if out[-1] == '{':
			out+= '"cd":"'+ip+'"'
		else:
			out+= ',"cd":"'+ip+'"'
	except Exception as e:
		Logger.info("%s" % str(e))
		start_vpn20()

	out+="}"
	return out






def start_vpn():
	os.system(r"kill `ps ax | grep openvpn | grep -v grep | awk '{print $1}'`")
	Logger.info("start vpn")
	subprocess.Popen(r"openvpn --daemon --config /root/vpnx/hippo.conf --script-security 3 --up /root/vpnx/up.sh",shell=True,close_fds=True)
	#os.system(r"openvpn --daemon --config /root/vpnx/hippo.conf --script-security 3 --up /root/vpnx/up.sh")
	time.sleep(5)

def start_vpn10():
	os.system(r"kill `ps ax | grep vpn10 | grep -v grep | awk '{print $1}'`")
	Logger.info("start vpn10")
	subprocess.Popen(r"vpn10 --daemon --config /root/vpnx/hippo10.conf --script-security 3 --up /root/vpnx/up10.sh",shell=True,close_fds=True)
	#os.system(r"vpn10 --daemon --config /root/vpnx/hippo10.conf --script-security 3 --up /root/vpnx/up10.sh")
	time.sleep(5)

def start_vpn20():
	os.system(r"kill `ps ax | grep vpn20 | grep -v grep | awk '{print $1}'`")
	Logger.info("start vpn20")
	subprocess.Popen(r"vpn20 --daemon --config /root/vpnx/hippo20.conf --script-security 3 --up /root/vpnx/up20.sh",shell=True,close_fds=True)
	#os.system(r"vpn20 --daemon --config /root/vpnx/hippo20.conf --script-security 3 --up /root/vpnx/up20.sh")
	time.sleep(5)


def monitorppp():
    global G_IP
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('64s','ppp0'))[20:24])
            s.close()
            if ip != G_IP:
                Logger.info("monitorppp change ...")
                send_heart_one()
        except Exception as e:
            #Logger.info("monitorppp %s" % str(e))
            pass
        time.sleep(5)


def mycrontask():
	os.system(r"echo 1 > /proc/sys/net/ipv4/ip_forward")
	os.system(r"iptables -t nat -D POSTROUTING  -o ppp0 -j MASQUERADE")
	os.system(r"iptables -t nat -A POSTROUTING  -o ppp0 -j MASQUERADE")
	os.system(r"iptables -t nat -D POSTROUTING  -o eth0 -j MASQUERADE")
	os.system(r"iptables -t nat -A POSTROUTING  -o eth0 -j MASQUERADE")
	os.system(r"iptables -t nat -D POSTROUTING  -o eth1 -j MASQUERADE")
	os.system(r"iptables -t nat -A POSTROUTING  -o eth1 -j MASQUERADE")
	os.system(r"iptables -t filter -N ARM_LIULIANG")
	Logger.info(get_tapip())
	min = random.randint(1,59)
	#sched = BlockingScheduler()
	sched.add_job(my_job2, 'cron', hour='6-23', minute=min, misfire_grace_time=600)
	sched.add_job(my_job1, 'cron', hour=0, minute=0, misfire_grace_time=600)
	sched.add_job(my_job3, 'cron', hour=3, minute=min, misfire_grace_time=600)
	sched.add_job(my_job5, 'cron', hour=2, minute=0, misfire_grace_time=600)
	sched.add_job(my_job4, 'cron', hour=10, minute=min, misfire_grace_time=600)
	#sched.add_job(monitorppp, 'interval', seconds=5)
	Logger.info("hour 6 min %s" % min)
	sched.start()

def mychange():
    Logger.info("mychange go")
    while True:
        try:
            cmd_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fcntl.fcntl(cmd_s.fileno(),fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            cmd_s.bind(("0.0.0.0",10070))
            break
        except Exception as e:
            Logger.info("mychange err" + str(e))
            time.sleep(120)
        Logger.info("mychange init")
    while True:
        try:
            rl, wl, error = select.select([cmd_s],[],[],60)
            if cmd_s in rl:
                try:
                    data,server_addr = cmd_s.recvfrom(64)
                    uuidf=open('/root/vpnx/uuid','r')
                    uuid = uuidf.read().strip()
                    if uuid in data:
                        Logger.info("change uuid ok %s" % uuid)
                        proc = subprocess.Popen(r"pppoe-stop",shell=True,close_fds=True)
                        i = 10
                        while i > 0:
                            if proc.poll() != None:
                                break
                            time.sleep(1)
                            i -= 1
                        if proc.poll() == None:
                            Logger.info("stop time out .......")
                            proc.kill()
                        proc = subprocess.Popen(r"pppoe-start",shell=True,close_fds=True)
                        i = 10
                        while i > 0:
                            if proc.poll() != None:
                                break
                            time.sleep(1)
                            i -= 1
                        if proc.poll() == None:
                            Logger.info("start time out .......")
                            #proc.kill()
                        uuidf.close()
                        if send_heart_one() == 1:
                            time.sleep(20)
                            send_heart_one()
                    else:
                        Logger.info("change uuid err %s %s" % (uuid,data))
                        uuidf.close()
                except Exception as e:
                    Logger.info("change %s" % str(e))
                    #print "go"
        except Exception as e:
            print "Except ",str(e)
            Logger.info("Except %s" % str(e))
            time.sleep(10)
            Logger.info("Except ok")



if __name__ == '__main__':
	Logger.info("step 1")
	loadv2ray()
	Logger.info("step 2")

	t = threading.Timer(1, mycrontask)
	t.start()
	Logger.info("step 3")

	t2 = threading.Timer(1, monitorppp)
	t2.start()
	Logger.info("step 4")

	t1 = threading.Timer(1, mychange)
	t1.start()
	Logger.info("step 5")

	send_heart()
	Logger.info("step 6")

	app.run(debug=True,host='0.0.0.0',port=7008,threaded=True,use_reloader=False)   
