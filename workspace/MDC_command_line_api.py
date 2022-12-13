import requests


print("Enter your apikey: ")
apikey = input()
print("Enter an option")
print("1. API version")
print("2. Retrieving scan reports using a hash Copy")
print("3. API info copy")
option = input()


match option:
    case "1":
        #API version 
        url = "https://api.metadefender.com/v4/status/version"
        headers = {}
        response = requests.get(url, headers=headers)
        print(response.json())
    case "2":
        #Retriving scan reports using a data hash 
        print("Enter your hash: ")
        hash = input()
        url = "https://api.metadefender.com/v4/hash/{hash}"
        headers = {
         "apikey": "{apikey}"
        }
        response = requests.get(url, headers=headers)
        print(response.json())

    case "3":
        #API version 
        url = "https://api.metadefender.com/v4/status/version"
        headers = {}
        response = requests.get(url, headers=headers)
        print(response.json())
    case _:
        print("Invalid input.")



