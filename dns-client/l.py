import requests
from bs4 import BeautifulSoup

# Step 1: Start a session
session = requests.Session()

# Step 2: Get the login page (to get hidden fields and cookies)
url = "https://10.240.240.1:6081/php/uid.php?vsys=1&rule=0"
login_page = session.get(url, verify=False)
soup = BeautifulSoup(login_page.text, "html.parser")

# Step 3: Extract hidden form fields (if any)
inputStr = soup.find("input", {"name": "inputStr"})["value"]
escapeUser = soup.find("input", {"name": "escapeUser"})["value"]
preauthid = soup.find("input", {"name": "preauthid"})["value"]

# Step 4: Submit login form with those fields + credentials
data = {
    "inputStr": inputStr,
    "escapeUser": escapeUser,
    "preauthid": preauthid,
    "user": "222011001",
    "passwd": "Kulkarni@8",
    "ok": "Login"
}

response = session.post(url, data=data, verify=False)

# Step 5: Check if login was successful
print("Status:", response.status_code)
print("Body:", response.text[:1000])  # Print first 1000 characters

