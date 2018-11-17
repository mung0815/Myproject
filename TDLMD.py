from __future__ import print_function
import requests
import json
import csv
import time
import zipfile
import os
from datetime import datetime
import pefile
from capstone import *
import sys
import os.path
import re
import math
import numpy as np
from itertools import chain
from collections import Counter
import nltk
from nltk.util import ngrams  # This is the ngram magic.


def disassemble(file_path):
    pe = pefile.PE(file_path)

    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(eop)
    #code_section = find_entry_point_section(pe, eop)
    #print(code_section)
    #code_dump = code_section.get_data(eop)
    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    var1 = var2 + f
    cf = open(var1, 'w')
    for i in md.disasm(code_dump, code_addr):
       if len(i.operands) == 2:
          cf.write(i.mnemonic + str(i.operands[0].type) + str(i.operands[1].type) + " ")
          #cf.write(i.mnemonic + i.op_str.replace(" ", "") + " ")
       elif len(i.operands) == 1:
          cf.write(i.mnemonic + str(i.operands[0].type) + " ")
          #cf.write(i.mnemonic + i.op_str.replace(" ", "") + " ")

          #else:
           #cf.write(i.mnemonic + " " + i.op_str + " ")


    pe.close()
    cf.close()


def rich_sig(file_path):
    pe = pefile.PE(file_path)
    rich_re = pe.parse_rich_header()
    a = list(rich_re.values())
    a = a[4]
    for k in range(int(len(a)/2)):
        del a[k + 1]
    a = a[:6]
    a = tuple(a)
    return a


def get_tuples_nosentences(txt):
    if not txt: return None
    ng = ngrams(re_stripper_alpha.sub(' ', txt).split(), NGRAM)
    return list(ng)


def jaccard_distance(a, b):
    a = set(a)
    b = set(b)
    return 1.0 * len(a & b) / len(a | b)


def cosine_similarity_ngrams(a, b):
    vec1 = Counter(a)
    vec2 = Counter(b)

    intersection = set(vec1.keys()) & set(vec2.keys())
    numerator = sum([vec1[x] * vec2[x] for x in intersection])

    sum1 = sum([vec1[x] ** 2 for x in vec1.keys()])
    sum2 = sum([vec2[x] ** 2 for x in vec2.keys()])
    denominator = math.sqrt(sum1) * math.sqrt(sum2)

    if not denominator:
        return 0.0
    return float(numerator) / denominator


def get_md5_hash_from_file(file_obj):
    """
    Read a CSV file using csv.DictReader
    """
    result = []
    reader = csv.DictReader(file_obj, delimiter=',')
    for line in reader:
       result.append(line["MD5hash"])
    return result

save_folder = "E:/mal" + str(datetime.today().month) + str(datetime.today().day - 1) + "/"
if not os.path.isdir(save_folder) :
	os.mkdir(save_folder)

tdate = str(datetime.today().month) + str(datetime.today().day - 1)
save_file = "C:/scripts/CP/THash" + tdate

#hash_path = "C:/scripts/CP/THash.csv"
hash_path = save_file + ".csv"
#hash_path = "C:/output/THash.csv"
out_csv_file = open(hash_path, "wt")
writer = csv.writer(out_csv_file, delimiter=',')
writer.writerow(["MD5hash"])


yearmonth = str(datetime.today().year) + "-" + str(datetime.today().month) + "-"

for k in range(datetime.today().day - 3, datetime.today().day - 2):
    for i in range(0, 24):
      for j in range(0, 59):
        start_date = yearmonth + str(k).rjust(2, '0') + " " + str(i).rjust(2, '0') + ":" + str(j).rjust(2, '0') + ":00"
        end_date = yearmonth + str(k).rjust(2, '0') + " " + str(i).rjust(2, '0') + ":" + str(j+1).rjust(2, '0') + ":00"
        print(start_date, end_date, hash_path)

        #params = {'api_key': 'E7217A420C279065AC198B83D26245BEA5E241F971DBB6B9935B0FF350E5F366', 'tag': 'dll_32bit', 'start':start_date, 'end':end_date, 'limit':10000}
        params = {'api_key': 'E7217A420C279065AC198B83D26245BEA5E241F971DBB6B9935B0FF350E5F366', 'tag': 'exe_32bit', 'start':start_date, 'end':end_date, 'limit':10000}

        resp = requests.get('https://private.api.malwares.com/v3/tag/search', params=params, verify=False)

        resp_json = resp.json()
        try:
            taglist = resp_json['list']

        except:
            pass

        hashlist = []
        for taginfo in taglist:
            hashlist.append(taginfo['sha256'])

        count=0

        for mymd5 in hashlist:
            writer.writerow([mymd5])
            count=count+1

        print(count)

out_csv_file.close()



#file download --------------------------------------------------------------------------------


in_file_path = hash_path
# out_file_path= "C:/output/V_NK.csv"

fileobj = open(in_file_path, "r")
md5hashes = get_md5_hash_from_file(fileobj)
fileobj.close()

for mymd5 in md5hashes:
    params = {'api_key': 'E7217A420C279065AC198B83D26245BEA5E241F971DBB6B9935B0FF350E5F366', 'hash': mymd5}
    response = requests.get('https://private.api.malwares.com/v3/file/download', params=params, verify=False)
    downloaded_file = response.content

    if len(downloaded_file) > 0 and len(downloaded_file) < 5000000:
       # fo = open("C:/scripts/MKIDA/mal/" + mymd5 + ".zip", "wb")
        fo = open(save_folder + mymd5 + ".zip", "wb")
        fo.write(downloaded_file)
        fo.close()
        print("\n\tMalware Downloaded to File -- " + mymd5)
    else:
        print(" -- Not Found for Download")


# zip extract --------------------------------------------------------------------------------

#zip_file_path = 'C:/scripts/MKIDA/mal/'
zip_file_path = save_folder
file_list = os.listdir(zip_file_path)
abs_path = []
count = 0
for a in file_list:
#    x = zip_file_path + a

    abs_path.append(a)
for f in abs_path:
  try:
      zip=zipfile.ZipFile(zip_file_path + f)
      zip.extractall(zip_file_path)
      zip.close()
  except:
      pass
  os.remove(zip_file_path + f)
  count = count + 1
  print(count)



# jaccard similarity(rich header) --------------------------------------------------------------------------------

NGRAM = 10
re_stripper_alpha = re.compile('[^a-zA-Z0-9]+')

save_rich_path = save_file + "rich" + ".csv"
rootdir = "C:/scripts/CP/md6rich"  # 기준파일

rich_csv_file = open(save_rich_path, "wt")
writer = csv.writer(rich_csv_file, delimiter=',')
writer.writerow(["MD5hash"])

for subdir, dirs, files in os.walk(rootdir):
    for file in files:
        input_file = rootdir + '/' + file
        fsize = os.path.getsize(input_file)
        print("")
        print(input_file)
        writer.writerow([input_file])
        a = rich_sig(input_file)
        brootdir = save_folder
        #brootdir = 'E:/mal1021'  # 비교대상 파일
        for bsubdir, bdirs, bfiles in os.walk(brootdir):
            for bfile in bfiles:
                binput_file = brootdir + bfile
                bfsize = os.path.getsize(binput_file)
                if bfsize > 500000:
                    continue

                try:
                    b = rich_sig(binput_file)
                except:
                    continue

                try:

                    if jaccard_distance(a, b) == 1:
                        print(binput_file)
                        writer.writerow([binput_file])
                        print("Jaccard: {}".format(jaccard_distance(a, b)))
                except:
                    continue
rich_csv_file.close()


# opcode creator --------------------------------------------------------------------------------


op_folder = "C:/scripts/CP/opcode" + tdate +"/"
if not os.path.isdir(op_folder) :
	os.mkdir(op_folder)

var2 = op_folder

mal_path = "E:/mal" + tdate +"/"
#var2 = 'C:\scripts\CP\opcode'
file_list = os.listdir(mal_path)
abs_path = []
count = 0
for a in file_list:
    abs_path.append(a)

for f in abs_path:
  try:
      disassemble(mal_path + f)
  except:
      pass

#  try:
#      os.remove(mal_path + f)
#  except:
#      pass

  count = count + 1
  print(count)


# opcode similarity --------------------------------------------------------------------------------

save_opcode_path = save_file + "opcode" + ".csv"

opcode_csv_file = open(save_opcode_path, "wt")
writer = csv.writer(opcode_csv_file, delimiter=',')
writer.writerow(["MD5hash"])


rootdir = "C:\scripts\CP\md6"  # 기준파일
for subdir, dirs, files in os.walk(rootdir):
    for file in files:
        input_file = rootdir + '/' + file
        fsize = os.path.getsize(input_file)
        print("")
        print(input_file)
        writer.writerow([input_file])
        f1 = open(input_file, 'r')
        farray = f1.read()
        a = get_tuples_nosentences(farray)

        brootdir = op_folder  # 비교대상 파일
        for bsubdir, bdirs, bfiles in os.walk(brootdir):
            for bfile in bfiles:
                binput_file = brootdir + '/' + bfile
                bfsize = os.path.getsize(binput_file)
                if bfsize > 500000:
                    continue
                f2 = open(binput_file, 'r')
                bfarray = f2.read()
                b = get_tuples_nosentences(bfarray)
                try:
                    if jaccard_distance(a, b) > 0.3 and cosine_similarity_ngrams(a, b) > 0.5:
                        print(binput_file)
                        writer.writerow([binput_file])
                        writer.writerow(["Jaccard: {}   Cosine: {}".format(jaccard_distance(a, b), cosine_similarity_ngrams(a, b))])
                        print("Jaccard: {}   Cosine: {}".format(jaccard_distance(a, b), cosine_similarity_ngrams(a, b)))
                except:
                    continue
                f2.close()

        f1.close()
opcode_csv_file.close()