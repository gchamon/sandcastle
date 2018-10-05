#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, commands, requests, random, string
from argparse import ArgumentParser

print """
   ____             __             __  __   
  / __/__ ____  ___/ /______ ____ / /_/ /__ 
 _\ \/ _ `/ _ \/ _  / __/ _ `(_-</ __/ / -_)
/___/\_,_/_//_/\_,_/\__/\_,_/___/\__/_/\__/ 
                                            
S3 bucket enumeration // release v1.2.5 // ysx

"""
#Create file for write check
filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '.txt'

targetStem = ""
inputFile = ""
bucketFile = ""

parser = ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-t", "--target", dest="targetStem",
                    help="Select a target stem name (e.g. 'shopify')", metavar="targetStem")
group.add_argument("-f", "--file", dest="inputFile",
                    help="Select a target list file", metavar="inputFile")
parser.add_argument("-b", "--bucket-list", dest="bucketFile",
                    help="Select a bucket permutation file (default: bucket-names.txt)", default="bucket-names.txt", metavar="bucketFile")
parser.add_argument("-o", "--output", dest="outputFile",
                    help="Select a output file", default="", metavar="outputFile")
args = parser.parse_args()


def checkBuckets(target):
	for name in bucketNames:
		for c in {"-",".","_",""}:
			for l in (True,False):
				if(l):
					bucketName = target + c + name
				else:
					bucketName = name + c + target
				r = requests.head("http://%s.s3.amazonaws.com" % bucketName)
				if r.status_code != 404:
					print "[+] Checking potential match: %s --> %s" % (bucketName, r.status_code)
					readCheck = commands.getoutput("aws s3 ls s3://%s" % bucketName)
					if "The specified bucket does not exist" not in readCheck:
						writeCheck = commands.getoutput("aws s3 mv %s s3://%s" % (filename, bucketName))
						if args.outputFile:
							outFile.write("[+] Found a match: %s --> %s\n" % (bucketName, r.status_code))
							outFile.write("[+] Read access test:%s\n" % readCheck)
							outFile.write("[+] Write access test:%s\n" % writeCheck)
						print "[+] Checking read access..."
						print readCheck
						print "[+] Checking write access..."
						print writeCheck

if __name__ == "__main__":	
	open(filename,'a').close()
	with open(args.bucketFile, 'r') as b: 
		bucketNames = [line.strip() for line in b] 
		lineCount = len(bucketNames)
		b.close()
	if args.outputFile:
		outFile = open(args.outputFile,"w")

	if(args.inputFile):
		with open(args.inputFile, 'r') as f: 
			targetNames = [line.strip() for line in f]
			f.close()
		for target in targetNames:
			print "[*] Commencing enumeration of '%s', reading %i lines from '%s'." % (target, lineCount, b.name)
			checkBuckets(target)
			print "[*] Enumeration of '%s' buckets complete." % (target)
	else:
		print "[*] Commencing enumeration of '%s', reading %i lines from '%s'." % (args.targetStem, lineCount, b.name)
		checkBuckets(args.targetStem)
		print "[*] Enumeration of '%s' buckets complete." % (args.targetStem)
	try:
		os.remove(filename)
	except:
		pass
	try:
		outFile.close()
	except:
		pass
