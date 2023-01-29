#!/usr/bin/env python3

'''                                       '''

    ######################################
    #        Ahmad Reza Parsi Zadeh      #
    #  Nuclei-Subfinder Automation  tool #
    ######################################


'''                                       '''
results = []
#-------------------------------------------------- COLORS ------------------------------------------------------------#
class Colors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RED1 = '\033[31m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'

#------------------------------------- Handling Errors and Installing Requirements ------------------------------------#
try:
    from fastapi import FastAPI, requests, Form
    from typing import Optional
    from datetime import date
    from pydantic import BaseModel
    from typing import Union
    from tkinter import *
    import os
    import subprocess
    import asyncio
    import json
    import sys
    import socket
    import uuid
    import tkinter as tk
    import mysql.connecto
    import Username as Username
    import password as password
    import login



except Exception as e_import:
    print(e_import)
    print(Colors.YELLOW + "\n[" + Colors.RED + "-" + Colors.YELLOW +
          "] ERROR requirements missing try to install the requirements: pip3 install -r requirements.txt" + Colors.END)
    YN_ANSWER = input(Colors.YELLOW + "Do you want to install the requirement? (Y/N)")
    GO_ANSWER = input(Colors.YELLOW + "Do you have GO installed without any deficiencies and errors?")
    if YN_ANSWER[0:3].lower() == "yes" or YN_ANSWER[0].lower() == "y":
        try:
            os.system("pip3 install -r requirements.txt")
        except Exception as e_requirements:
            print(e_requirements)
            print(Colors.RED + "Unable to install the requirements :(\n")
            print(Colors.YELLOW + "Check your internet connection\n")
            print(Colors.YELLOW + "Check if you have installed primitive packages like os, sys or even pip itself\n")
            exit(0)
    else :
        print(Colors.RED1 + "Installation failed\n")
        print("Quiting the program ...\n")
    exit(0)


    if GO_ANSWER[0:3].lower() == "yes" or YN_ANSWER[0].lower() == "y":
        subprocess.run(["go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"], shell=True)
        subprocess.run(["go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"], shell=True)

    else:
        subprocess.run(
            [str(os.getcwd()) + "/go/bin/go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            shell=True)
        subprocess.run(
            [str(os.getcwd()) + "/go/bin/go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"],
            shell=True)

########################################################################################################################

app = FastAPI()

os.environ["GOPATH"] = str(os.getcwd())+"/go/bin/tools"
os.environ["GOBIN"] = str(os.getcwd())+"/go/bin"
subprocess.run(["chmod -R +x "+str(os.getcwd())+"/go/bin/go"], shell=True)


#---------------------------------------------------- Login Page ------------------------------------------------------#



def submitact():
    user = Username.get()
    passw = password.get()

    print(f"The name entered by you is {user} {passw}")

    logintodb(user, passw)


def logintodb(user, passw):
    # If password is enetered by the
    # user
    if passw:
        db = mysql.connector.connect(host="localhost",
                                     user=user,
                                     password=passw,
                                     db="College")
        cursor = db.cursor()

    # If no password is enetered by the
    # user
    else:
        db = mysql.connector.connect(host="localhost",
                                     user=user,
                                     db="College")
        cursor = db.cursor()

    # A Table in the database
    savequery = "select * from STUDENT"

    try:
        cursor.execute(savequery)
        myresult = cursor.fetchall()

        # Printing the result of the
        # query
        for x in myresult:
            print(x)
        print("Query Executed successfully")

    except:
        db.rollback()
        print("Error occurred")

def Hamravesh_login_page():
    root = tk.Tk()
    root.geometry("300x300")
    root.title("Hamravesh Login Page")

    # Defining the first row
    lblfrstrow = tk.Label(root, text="Username -", )
    lblfrstrow.place(x=50, y=20)

    Username = tk.Entry(root, width=35)
    Username.place(x=150, y=20, width=100)

    lblsecrow = tk.Label(root, text="Password -")
    lblsecrow.place(x=50, y=50)

    password = tk.Entry(root, width=35)
    password.place(x=150, y=50, width=100)

    submitbtn = tk.Button(root, text="Login",
                          bg='blue', command=submitact)
    submitbtn.place(x=150, y=135, width=55)

    root.mainloop()

Hamravesh_login_page()
domain_id_json_list = {"domain_name" : " ",  "scan_id" : " "}
jsonString = json.dumps(domain_id_json_list)


#-------------------------------------------------- Domain ------------------------------------------------------------#
def domain_checking(domain:str):
    r = requests.get("https://" + domain, timeout=2)
    return r.status_code


@app.post("/api/scan/")
async def post_uuid(domain: str = Form()):
    f = open('domain_id_json_list.json')
    data = json.load(f)
    for key in data:
        if key == domain:
            return data[key]
        else:
            data.append({"domain_name" : domain , "scan_id" : uuid.uuid4()})
            return {"domain_name": domain, "scan_id": uuid.uuid4()}

#-------------------------------------------- API Automation Scanner --------------------------------------------------#
@app.get("/api/result/{domain}")
async def subfinder_nuclei_scanner(domain:str, target_name: str, autoscan: bool, tags: Optional[str] = None):
    special_characters = """"!@# $%^&*'()}{[]|\`+?_=,<>/"""

    # subfinder doesn't accept http domains you should use -k switch to ignore it!
    if 'http' in domain:
        return "Error Input"

    try:
        if any(c in special_characters for c in domain):
            return "Error Input"

        # Just check if the domain is responsible
        if domain_checking(domain):

            out = await asyncio.create_subprocess_shell(str(os.getcwd()) + "/go/bin/subfinder -d " + str(domain),
                                                        stdout=subprocess.PIPE)

            output = await out.communicate()

            for subs in output[0].decode().split('\n'):
                num = 1
                if len(subs) != 0:
                    out = subprocess.Popen(str(os.getcwd()) + "/go/bin/nuclei -u " + str(subs) + " -as -json",
                                           shell=True,
                                           stdout=subprocess.PIPE)
                    output = out.communicate()
                    data = []
                    for result in output[0].decode().split('\n'):
                        if len(result) != 0:
                            output_json = json.loads(result)
                            data.append(output_json)
                    sub_domain = {f'sub{num}': subs, 'result': data ,'ip': socket.gethostbyname(subs), 'scan_id': uuid.uuid4()}
                    results.append(sub_domain)

                    num += 1
            return {'response': results}

    except Exception as e:
        return {'message': "Error, Please try again!"}

# --------------------------------------------------- EOF ------------------------------------------------------------ #