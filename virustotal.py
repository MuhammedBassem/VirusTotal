import requests, bs4
import json
API_KEY = '3f211a1a2f3e0092832063970c780db4391d79ba15ee907f7c950d870e54a84f'






    
print("Please choose what do you want to scan:")
print("[ 1=HASH, 2=URL, 3=DOMAIN, 4=IP ]")
INPUT= str(input())

def HASH():
  print("Please enter HASH:")
  victim = str(input())
  url = 'https://www.virustotal.com/vtapi/v2/file/report'
  params = {'apikey': API_KEY, 'resource':victim}
  response = requests.get(url, params=params)
  response_json = json.loads(response.content)
  if response_json['positives'] == 0:
    print("The Hash Not Malicious! ")
  elif response_json['positives'] > 0:
     print("The Hash Is Malicious ! ")
  else:
     print("The Hash you are looking for does not exist. Please try again ")


def URL():
  print("Please enter URL:")
  victim = str(input())
  url = 'https://www.virustotal.com/vtapi/v2/url/report'
  params = {'apikey': API_KEY, 'resource':victim}
  response = requests.get(url, params=params)
  response_json = json.loads(response.content)
  if response_json['positives'] == 0:
    print("The Url Not Malicious! ")
  elif response_json['positives'] > 0:
     print("The Url Is Malicious ! ")
  else:
     print("The Url you are looking for does not exist. Please try again ")


def DOMAIN():
  print("Please enter DOMAIN:")
  victim = str(input())
  url = 'https://www.virustotal.com/vtapi/v2/domain/report'
  params = {'apikey':API_KEY,'domain':victim}
  response = requests.get(url, params=params)
  response_json = json.loads(response.content)
  result = response_json['detected_referrer_samples']
  list = []
  for line in result:
    list.append(line['positives'])
  final_result = sum(list)
  if final_result == 0:
        print("The Domain Not Malicious! ")
  elif final_result > 0:
        print("The Domain Is Malicious ! ")
  else:
        print("The Domain you are looking for does not exist. Please try again ")


def IP():
  print("Please enter IP:")
  victim = str(input())
  url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
  params = {'apikey':API_KEY,'ip':victim}
  response = requests.get(url, params=params)
  response_json = json.loads(response.content)
  result = response_json['detected_downloaded_samples']
  list = []
  for line in result:
    list.append(line['positives'])
  final_result = sum(list)
  if final_result == 0:
    print("The Ip-Address Not Malicious! ")
  elif final_result > 0:
    print("The Ip-Address Is Malicious ! ")
  else:
    print("The Ip-Address you are looking for does not exist. Please try again")

if INPUT=="1":HASH()
elif INPUT=="2":URL()
elif INPUT=="3":DOMAIN()
elif INPUT=="4":IP()
