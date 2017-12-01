#!/usr/bin/env python
#coding:utf-8
#Author:se55i0n
#针对常见sql、No-sql数据库进行安全检查
import sys
import IPy
import time
import socket
import gevent
import argparse
from gevent import monkey
from multiprocessing.dummy import Pool as ThreadPool
from lib.config import *
from lib.exploit import *

monkey.patch_all()

class DBScanner(object):
	def __init__(self, target, thread):
		self.target = target
		self.thread = thread
		self.ips    = []
		self.ports  = []
		self.time   = time.time()
		self.get_ip()
		self.get_port()
		self.check = check()
	
	def get_ip(self):
		#获取待扫描地址段
		for ip in IPy.IP(self.target):
			self.ips.append(str(ip))

	def get_port(self):
		self.ports = list(p for p in service.itervalues())

	def scan(self, ip, port):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(0.2)
			if s.connect_ex((ip, port)) == 0:
				self.handle(ip, port)
		except Exception as e:
			pass
		finally:
			s.close()

	def handle(self, ip, port):
		for v,k in service.iteritems():
			if k == str(port):
				if v == 'mysql':
					self.check.mysql(ip)
				elif v == 'mssql':
					self.check.mssql(ip)
				elif v == 'oracle':
					self.check.oracle(ip)
				elif v == 'postgresql':
					self.check.postgresql(ip)
				elif v == 'redis':
					self.check.redis(ip)
				elif v == 'mongodb':
					self.check.mongodb(ip)
				elif v == 'memcached':
					self.check.memcached(ip)
				else:
					self.check.elasticsearch(ip)

	def start(self, ip):
		try:
			gevents = []
			for port in self.ports:
				gevents.append(gevent.spawn(self.scan, ip, int(port)))
			gevent.joinall(gevents)
		except Exception as e:
			pass

	def run(self):
		try:
			pool = ThreadPool(processes=self.thread)
			pool.map_async(self.start, self.ips).get(0xffff)
			pool.close()
			pool.join()
		except Exception as e:
			pass
		except KeyboardInterrupt:
			print u'\n{}[-] 用户终止扫描...{}'.format(R, W)
			sys.exit(1)
		finally:
			print '-'*55
			print u'{}[+] 扫描完成耗时 {} 秒.{}'.format(O, time.time()-self.time, W) 

def banner():
	banner = '''
    ____  ____ _____
   / __ \/ __ ) ___/_________ _____  ____  ___  _____
  / / / / __  \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /_/ / /_/ /__/ / /__/ /_/ / / / / / / /  __/ /
/_____/_____/____/\___/\__,_/_/ /_/_/ /_/\___/_/
    '''
	print B + banner + W
	print '-'*55

def main():
	banner()
	parser = argparse.ArgumentParser(description='Example: python {} 192.168.1.0/24'.format(sys.argv[0]))
	parser.add_argument('target', help=u'192.168.1.0/24')
	parser.add_argument('-t', type=int, default=50, dest='thread', help=u'线程数(默认50)')
	args   = parser.parse_args()
	myscan = DBScanner(args.target, args.thread)
	myscan.run()

if __name__ == '__main__':
	main()
