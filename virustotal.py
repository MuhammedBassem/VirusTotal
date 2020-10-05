import requests
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
  print(response.json())

def URL():
  print("Please enter URL:")
  victim = str(input())
  url = 'https://www.virustotal.com/vtapi/v2/url/report'
  params = {'apikey': API_KEY, 'resource':victim}
  response = requests.get(url, params=params)
  print(response.json())

def DOMAIN():
  print("Please enter DOMAIN:")
  victim = str(input())
  url = 'https://www.virustotal.com/vtapi/v2/domain/report'
  params = {'apikey':API_KEY,'domain':victim}
  response = requests.get(url, params=params)
  print(response.json())

def IP():
  print("Please enter IP:")
  victim = str(input())
  url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
  params = {'apikey':API_KEY,'ip':victim}
  response = requests.get(url, params=params)
  print(response.json())


if INPUT=="1":HASH()
elif INPUT=="2":URL()
elif INPUT=="3":DOMAIN()
elif INPUT=="4":IP()
