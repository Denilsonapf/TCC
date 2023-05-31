import os
import time
import ipapi
import pickle
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

def parse_eml(Lines):
    state = ""
    data = {}

    # Strips the newline character
    for line in Lines:
        if state.startswith("httpd"):
            if not line.strip():
                state = "httpd"
                continue
            if line.strip() == "---------------------- httpd End -------------------------":
                state = ""
                continue
            if state == "httpd.ips":
                data[state].append(line.strip())
            if state.startswith("httpd.error"):
                splits = line.strip().split(': ')
                if len(splits) > 1:
                    path = splits[0]
                    times = int(splits[1].strip().split(' ')[0])
                    data[state].append([path, times])
                else:
                    state = "httpd.error." + line.strip().split(' ')[0]
                    data[state] = []
            if line.strip().startswith("A total of"):
                state = "httpd.ips"
                data[state] = []
            if line.strip().startswith("400 Bad Request"):
                state = "httpd.error.400"
                data[state] = []
            if line.strip().startswith("403 Forbidden"):
                state = "httpd.error.403"
                data[state] = []    
            if line.strip().startswith("404 Not Found"):
                state = "httpd.error.404"
                data[state] = []
            if line.strip().startswith("405 Method Not Allowed"):
                state = "httpd.error.405"
                data[state] = []    
            if line.strip().startswith("407 Proxy Authentication Required"):
                state = "httpd.error.407"
                data[state] = []
            if line.strip().startswith("408 Request Timeout"):
                state = "httpd.error.408"
                data[state] = []
            if line.strip().startswith("503 Service Unavailable"):
                state = "httpd.error.503"
                data[state] = [] 

        if state.startswith("pam"):
            if not line.strip():
                state = "pam"
                continue
            if line.strip() == "---------------------- pam_unix End -------------------------":
                state = ""
                continue
            if state == "pam.af":
                splits = line.strip().split(': ')
                if len(splits) > 1:
                    username = splits[0].split(' ')[0]
                    ip = splits[0].split(' ')[1][1:-1]
                    times = int(splits[1].strip().split(' ')[0])
                    data[state].append([username, ip, times])
                else:
                    state = "pam"
            if state == "pam.iu":
                splits = line.strip().split(': ')
                if len(splits) > 1:
                    username = splits[0]
                    times = int(splits[1].strip().split(' ')[0])
                    data[state].append([username, times])
                else:
                    state = "pam"
                            
            if line.strip().startswith("Authentication Failures"):
                state = "pam.af"
                data[state] = []
            if line.strip().startswith("Invalid Users"):
                state = "pam.iu"
                data[state] = []
                
        if state.startswith("sshd"):
            if not line.strip():
                state = "sshd"
                continue
            if line.strip() == "---------------------- SSHD End -------------------------":
                state = ""
                continue

            if state.startswith("sshd."):
                splits = line.strip().split(': ')
                if len(splits) > 1:
                    ip = splits[0].split(' ')[0]
                    times = int(splits[1].strip().split(' ')[0])
                    data[state].append([ip, times])
                else:
                    state = "sshd"

            if line.strip().startswith("Failed logins"):
                state = "sshd.failed"
                data[state] = []
            if line.strip().startswith("Illegal users"):
                state = "sshd.iu"
                data[state] = []

        if line.strip() == "--------------------- httpd Begin ------------------------":
            state = "httpd"
            #print("Line: {}".format(line.strip()))

        if line.strip() == "--------------------- pam_unix Begin ------------------------":
            state = "pam"
            #print("Line: {}".format(line.strip()))

        if line.strip() == "--------------------- SSHD Begin ------------------------":
            state = "sshd"
            #print("Line: {}".format(line.strip()))
            
    #print(data)
    return data
   

def getipdata(ip):
    filename = os.path.join(os.getcwd(), "data", ip.replace('.', '-'))
    print(filename)
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            ipdata = pickle.load(f)
    else:
        ipdata = ipapi.location(ip=ip)
        #time.sleep(1)
        with open(filename, 'wb') as f:
            pickle.dump(ipdata, f)
    return ipdata

def getipbrazilian(ip):
    filename = os.path.join(os.getcwd(), "data", ip.replace('.', '-'))
    print(filename)
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            ipdata = pickle.load(f)
    else:
        ipdata = ipapi.location(ip=ip, output='country')
        #time.sleep(1)
        with open(filename, 'wb') as f:
            pickle.dump(ipdata, f)
    return ipdata

def data_analysis(alldata):

    # Quantidade de IPs que acessaram o Web server por dia
    x = []
    y = []
    for email in alldata:
        x.append(datetime.strptime(email, '%Y-%m-%d').date())
        for datatype in alldata[email]:
            if datatype == "httpd.ips":
                y.append(len(alldata[email]["httpd.ips"]))
    
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%d/%m/%Y'))
    plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=5))
    plt.bar(x,y)
    plt.gcf().autofmt_xdate()
    plt.savefig('https.ips-days.pdf')
    plt.clf()

    # Quantidade de IPs que acessaram o Web server por dia
    for email in alldata:
        #print(email, alldata[email].keys())
        for datatype in alldata[email]:
            if datatype == "httpd.ips":
                for idx, ip in enumerate(alldata[email]["httpd.ips"]):
                    alldata[email]["httpd.ips"][idx] = getipdata(ip)
                break
        break
    count = {}
    for email in alldata:
        x.append(datetime.strptime(email, '%Y-%m-%d').date())
        for datatype in alldata[email]:
            if datatype == "httpd.ips":
                for ipdata in alldata[email]["httpd.ips"]:
                    country = ipdata["country_name"]
                    if country not in count:
                        count[country] = 0
                    count[country] += 1
                print(count)
                break
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('https.ips-country.pdf')
    plt.clf()
    #printar o total de error codes
    for email in alldata:
        #x.append(datetime.strptime(email, '%Y-%m-%d').date())
        count = {}
        for datatype in alldata[email]:
            if datatype.startswith("httpd.error"):
                errorcode = datatype[12:]
               
                for x in alldata[email][datatype]: 
                    if errorcode not in count:
                        count[errorcode] = 0
                    count[errorcode] +=x[1]
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('http.error.pdf')
    plt.clf()
    #printar o total de error codes de cada grupo
    for email in alldata:
        #x.append(datetime.strptime(email, '%Y-%m-%d').date())
        count = {}
        for datatype in alldata[email]:
            if datatype.startswith("httpd.error.404"):
               
                for x in alldata[email][datatype]: 
                    if "wordpress" in x[0].lower() or "wp" in x[0].lower():
                        groupname = "wordpress"
                    elif "ubuntu/dists" in x[0].lower():
                        groupname = "ubuntu/dists"
                    elif "mysql" in x[0].lower():
                        groupname = "mysql"
                    elif "phpmyadmin" in x[0].lower() or "php" in x[0].lower():
                        groupname = "phpmyadmin"
                    else: 
                        groupname = "other"
                    if groupname not in count:
                        count[groupname] = 0
                    count[groupname] +=x[1]
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('http.error_group.pdf')
    plt.clf()                 
                #exit()
    #printar o total de tentativas para cada usuário
    for email in alldata:
        #x.append(datetime.strptime(email, '%Y-%m-%d').date())
        count = {}
        for datatype in alldata[email]:
            if datatype.startswith("pam.af"):
               
                for x in alldata[email][datatype]: 
                    if "root" in x[0].lower():
                        username = "root"
                    elif "unknown" in x[0].lower():
                        username = "unknown"
                    elif "mail" in x[0].lower():
                        username = "mail"
                    elif "backup" in x[0].lower():
                        username = "backup"
                    elif "www-data" in x[0].lower():
                        username = "www-data"    
                    else: 
                        username = "other"
                    if username not in count:
                        count[username] = 0
                    count[username] +=x[2]
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('pam.af_user.pdf')
    plt.clf() 

     #printar o total de tentativas para o usuário inválido
    for email in alldata:
        x.append(datetime.strptime(email, '%Y-%m-%d').date())
        count = {}
        for datatype in alldata[email]:
            if datatype.startswith("pam.iu"):
               
                for x in alldata[email][datatype]: 
                    if "unknown account" in x[0].lower():
                        username = "Unknown Account"
                    if username not in count:
                        count[username] = 0
                    count[username] +=x[1]
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('pam.iu_invalid_user.pdf')
    plt.clf()   
    #printar o total de ips com falha
    x = ()
    y = ()
    count = {}
    #test = ipapi.location(ip='177.142.144.108', output='country')
    #print("Região do ip",test)
    for email in alldata:
        #x.append(datetime.strptime(email, '%Y-%m-%d').date())
        #count = {}
        iplist = []
        for datatype in alldata[email]:
            if datatype.startswith("pam.af"):
               
                for x in alldata[email][datatype]: 
                    iplist.append(x[1])
                iplist= list(set(iplist))
                count[datetime.strptime(email, '%Y-%m-%d').date()] = len(iplist)
        break
    plt.bar(count.keys(), count.values())
    print(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('pam.af_ip.pdf')
    plt.clf()       

    #printar o total de tentativas para cada país
    for email in alldata:
        #x.append(datetime.strptime(email, '%Y-%m-%d').date())
        count = {}
        for datatype in alldata[email]:
            if datatype.startswith("pam.af"):
               
                for x in alldata[email][datatype]:
                    filename = os.path.join(os.getcwd(), "data", ip.replace('.', '-'))
                    print(filename)
                    if os.path.exists(filename):
                        with open(filename, 'rb') as f:
                            test = pickle.load(f)
                            if test['country'] == 'BR':
                                region = test['region']
                                city = test['city']
                                if city not in count:
                                    count[city] = 0
                                count[city] += 1
                                if region not in count:
                                    count[region] = 0
                                count[region] += 1
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('pam.af_city.pdf')
    plt.clf()          
    #printar a quatidade de acessos inválidos 
    for email in alldata:
        #print(email, alldata[email].keys())
        count = {}
    for email in alldata:
        x.append(datetime.strptime(email, '%Y-%m-%d').date())
        for datatype in alldata[email]:
            if datatype == "pam.af":
                for ipdata in alldata[email]["httpd.ips"]:
                    country = ipdata["country_name"]
                    if country not in count:
                        count[country] = 0
                    count[country] += 1
                print(count)
                break
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('pam-af.pdf')
    plt.clf()

 # Quantidade de IPs que acessaram o Web server por dia
    x = []
    y = []
    for email in alldata:
        x.append(datetime.strptime(email, '%Y-%m-%d').date())
        for datatype in alldata[email]:
            if datatype == "sshd.failed":
                y.append(len(alldata[email]["sshd.failed"]))
    
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%d/%m/%Y'))
    plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=5))
    plt.bar(x,y)
    plt.gcf().autofmt_xdate()
    plt.savefig('sshd.ips-days.pdf')
    plt.clf()
#printar o total de tentativas para cada país
    for email in alldata:
        #x.append(datetime.strptime(email, '%Y-%m-%d').date())
        count = {}
        for datatype in alldata[email]:
            if datatype.startswith("sshd.failed"):
               
                for x in alldata[email][datatype]:
                    filename = os.path.join(os.getcwd(), "data", ip.replace('.', '-'))
                    print(filename)
                    if os.path.exists(filename):
                        with open(filename, 'rb') as f:
                            test = pickle.load(f)
                            country = test['country']
                            if country not in count:
                                count[country] = 0
                            count[country] += 1
        break
    plt.bar(count.keys(), count.values())
    plt.gcf().autofmt_xdate(rotation=45)
    plt.savefig('pam.sshd_coutry.pdf')
    plt.clf()   

### MAIN ###

alldata = {}

# Using readlines()
path = "files-julho"

# interação com todos os arquivos
for file in os.listdir(os.path.join(os.getcwd(), path)):
    #verificação se há ou não o tipo de arquivos
    if file.endswith(".eml"):
        #chamada para leitura dos arquivos na função
        with open(os.path.join(os.getcwd(), path, file), 'r') as f:
            Lines = f.readlines()
            alldata[file.split()[7]] = parse_eml(Lines)

data_analysis(alldata)


