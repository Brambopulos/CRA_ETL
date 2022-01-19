# etl_process.py v1.0
# Modified by Brandon Pimentel
# Current Revision 010922

import sys
import os
import csv
import tarfile
import zipfile
import argparse
import glob
import getpass
import pymysql
import sqlalchemy
import pandas as pd

# This will retrieve all info from etldb output if needed
#info = etldb.fetchall()
#for line in info:
# print(line)

# This gets every CSV, and can query specific CSVs (for each table) as so: '/lin_temp/**/*ss.csv'
# for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*.csv'), recursive=True):
#    print(filename)

parser = argparse.ArgumentParser(description='ETL Program; Brandon Pimentel 011922')
parser.add_argument("-d", "--debug", help="Prints verbose program information", action="store_true")
parser.add_argument("-u", "--user", help="MySQL Database Username (default: root)", default="root")
parser.add_argument("-l", "--location", help="MySQL Database Location (default: localhost)", default="localhost")
parser.add_argument("-n", "--name", help="MySQL Database Name (default: etldb)", default="etldb")

args = parser.parse_args()
pwd = getpass.getpass("Password for MySQL user '{}'? ".format(args.user))

def log(s):
    if args.debug:
        print(s)
    return

def formatIP(csvfile):
    df = pd.read_csv(csvfile)
    df = df.astype(object)
   # Darwin case; create columns to support new data, split IP and Port into new columns
    if not 'LocalPort' in df.columns:
        df.insert(5, 'LocalPort', None)
        df.insert(7, 'RemotePort', None)
        df['ProcessName'] = ""

        for (i, row) in df.iterrows():
            lAddress = df.at[i, 'LocalAddress']
            rAddress = df.at[i, 'RemoteAddress']
            if lAddress.count(".") > 1:
                df.at[i, 'LocalAddress'] = ".".join(lAddress.split(".", 4)[:4])
                df.at[i, 'LocalPort'] = lAddress.split(".")[4]
            if rAddress.count(".") > 1:
                df.at[i, 'RemoteAddress'] = ".".join(rAddress.split(".", 4)[:4])
                df.at[i, 'RemotePort'] = rAddress.split(".")[4]                
            if lAddress.count(".") == 1:
                df.at[i, 'LocalAddress'] = lAddress.split(".")[0]
                df.at[i, 'LocalPort'] = rAddress.split(".")[1]
            if rAddress.count(".") == 1:
                df.at[i, 'RemoteAddress'] = rAddress.split(".")[0]
                df.at[i, 'RemotePort'] = rAddress.split(".")[1]

        df = df.where(pd.notnull(df), "-")
        return df
    
    # Linux case; no new columns, split IP/port based on field content, split PID/process
    for (i, row) in df.iterrows():
        lAddress = df.at[i, 'LocalAddress']
        rAddress = df.at[i, 'RemoteAddress']
        if lAddress.count(":") > 1:
            df.at[i, 'LocalAddress'] = ":".join(lAddress.split(":", 3)[:3])
            df.at[i, 'LocalPort'] = lAddress.split(":")[3]
        if rAddress.count(":") > 1:
            df.at[i, 'RemoteAddress'] = ":".join(rAddress.split(":", 3)[:3])
            df.at[i, 'RemotePort'] = rAddress.split(":")[3]
        if lAddress.count(":") == 1:
            df.at[i, 'LocalAddress'] = lAddress.split(":")[0]
            df.at[i, 'LocalPort'] = lAddress.split(":")[1]
        if rAddress.count(":") == 1:
            df.at[i, 'RemoteAddress'] = rAddress.split(":")[0]
            df.at[i, 'RemotePort'] = rAddress.split(":")[1]

        pid = df.at[i, 'PID']
        if isinstance(pid, str) and "/" in pid:
            df.at[i, 'PID'] = pid.split("/")[0]
            df.at[i, 'ProcessName'] = pid.split("/")[1]

    df = df.where(pd.notnull(df), "-")
    return df

# def formatIP_SS(csvfile):
#     lAddress = df.at[i, 'LocalAddress']
#     rAddress = df.at[i, 'RemoteAddress']
#     if lAddress.count(":") > 1:
#         df.at[i, 'LocalAddress'] = ":".join(lAddress.split(":", 3)[:3])
#         df.at[i, 'LocalPort'] = lAddress.split(":")[3]
#     if rAddress.count(":") > 1:
#         df.at[i, 'RemoteAddress'] = ":".join(rAddress.split(":", 3)[:3])
#         df.at[i, 'RemotePort'] = rAddress.split(":")[3]
#     if lAddress.count(":") == 1:
#         df.at[i, 'LocalAddress'] = lAddress.split(":")[0]
#         df.at[i, 'LocalPort'] = lAddress.split(":")[1]
#     if rAddress.count(":") == 1:
#         df.at[i, 'RemoteAddress'] = rAddress.split(":")[0]
#         df.at[i, 'RemotePort'] = rAddress.split(":")[1]


def pullRows(csvfile):
    reader = csv.reader(csvfile, delimiter=',')
    next(reader)
    csvrows = list(reader)
    return csvrows


####### INITIALIZATION #######

# Detect files currently in dir
files = os.listdir(".")
cwd = os.getcwd()

# Initialize folders
# Create Unix temp folder
if not os.path.exists('lin_temp'):
    os.mkdir('lin_temp')

# Create Windows temp folder
if not os.path.exists('win_temp'):
    os.mkdir('win_temp')

# DIRECTORY; Unzip and Untar everything
for filename in files:
    if filename.endswith('.zip'):
        log('Unzipping ' + filename + "...")
        zip = zipfile.ZipFile(filename)
        zip.extractall(path='win_temp')

for filename in files:
    if filename.endswith('.tgz'):
        log('Decompressing ' + filename + '...')
        tar = tarfile.open(filename)
        tar.extractall(path='lin_temp')

# Prepare database
# Establish connection
etldb = sqlalchemy.create_engine("mysql+pymysql://{}:{}@{}".format(args.user, pwd, args.location))

log("Creating database...")
# Create ETL database
etldb.execute("CREATE DATABASE IF NOT EXISTS {}".format(args.name))
etldb.execute("USE {}".format(args.name))

log("Creating tables...")
# Create activecomms table
etldb.execute('''
CREATE TABLE IF NOT EXISTS activecomms(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    pid VARCHAR(255),
    process VARCHAR(255),
    servicename VARCHAR(255),
    path VARCHAR(255),
    servicestarttype VARCHAR(255),
    sha1 VARCHAR(255),
    md5 VARCHAR(255),
    commandline TEXT,
    connected VARCHAR(255),
    state VARCHAR(255),
    l_address VARCHAR(255),
    l_port VARCHAR(255),
    r_address VARCHAR(255),
    r_port VARCHAR(255));
''')

# Create allfiles table
etldb.execute('''
CREATE TABLE IF NOT EXISTS allfiles(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    length VARCHAR(255),
    directory VARCHAR(255),
    creationtime VARCHAR(255),
    lastwritetime VARCHAR(255),
    productversion VARCHAR(255),
    fileversion TEXT,
    description VARCHAR(255),
    sha1 VARCHAR(255),
    md5 VARCHAR(255));
''')


# Create allprofiles table
etldb.execute('''
CREATE TABLE IF NOT EXISTS allprofiles(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    length VARCHAR(255),
    directory VARCHAR(255),
    creationtime VARCHAR(255),
    lastwritetime VARCHAR(255),
    productversion VARCHAR(255),
    fileversion VARCHAR(255),
    description VARCHAR(255));
''')

# Create allprofiles_reg table
etldb.execute('''
CREATE TABLE IF NOT EXISTS allprofiles_reg(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    sid VARCHAR(255),
    pschildname VARCHAR(255),
    profileimagepath VARCHAR(255));
''')

# Create allusers table
etldb.execute('''
CREATE TABLE IF NOT EXISTS allusers(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    lastlogin VARCHAR(255),
    enabled VARCHAR(255),
    `groups` TEXT);
''')

# Create allusers_reg table
etldb.execute('''
CREATE TABLE IF NOT EXISTS allusers_reg(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    accounttype VARCHAR(255),
    caption VARCHAR(255),
    domain VARCHAR(255),
    sid VARCHAR(255),
    fullname VARCHAR(255),
    name VARCHAR(255));
''')

# Create amcache table
etldb.execute('''
CREATE TABLE IF NOT EXISTS amcache(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    command TEXT,
    path VARCHAR(255),
    lastmod VARCHAR(255));
''')

# Create authlog table
etldb.execute('''
CREATE TABLE IF NOT EXISTS authlog(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    date VARCHAR(255),
    user VARCHAR(255),
    homedir VARCHAR(255),
    method VARCHAR(255),
    command TEXT);
''')

# Create commandshistory table
etldb.execute('''
CREATE TABLE IF NOT EXISTS commandshistory(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    command TEXT);
''')

# Create cron table
etldb.execute('''
CREATE TABLE IF NOT EXISTS cron(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    datemodified VARCHAR(255),
    command TEXT,
    time VARCHAR(255));
''')

# Create dnscache table
etldb.execute('''
CREATE TABLE IF NOT EXISTS dnscache(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    dns VARCHAR(255));
''')

# Create dnsresolvers table
etldb.execute('''
CREATE TABLE IF NOT EXISTS dnsresolvers(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    dnstype VARCHAR(255),
    address VARCHAR(255));
''')

# Create etc_passwd table
etldb.execute('''
CREATE TABLE IF NOT EXISTS etc_passwd(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    user VARCHAR(255),
    uid VARCHAR(255),
    gid VARCHAR(255),
    homedir VARCHAR(255),
    shell VARCHAR(255));
''')

# Create launchctl table
etldb.execute('''
CREATE TABLE IF NOT EXISTS launchctl(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    service VARCHAR(255),
    enabletransactions VARCHAR(255),
    limitloadtype VARCHAR(255),
    program VARCHAR(255),
    timeout VARCHAR(255),
    ondemand VARCHAR(255),
    machservices TEXT,
    programarguments VARCHAR(255));
''')

# Create logonevents table
etldb.execute('''
CREATE TABLE IF NOT EXISTS logonevents(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    user VARCHAR(255),
    logontype VARCHAR(255),
    date VARCHAR(255),
    time VARCHAR(255),
    duration VARCHAR(255));
''')

# Create mainusergroups table
etldb.execute('''
CREATE TABLE IF NOT EXISTS mainusergroups(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    user VARCHAR(255),
    uid VARCHAR(255),
    gid VARCHAR(255),
    gname VARCHAR(255));
''')

# Create netstat table
etldb.execute('''
CREATE TABLE IF NOT EXISTS netstat(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    protocol VARCHAR(255),
    l_address VARCHAR(255),
    l_port VARCHAR(255),
    r_address VARCHAR(255),
    r_port VARCHAR(255),
    state VARCHAR(255),
    pid VARCHAR(255),
    process VARCHAR(255));
''')

# Create nic table
etldb.execute('''
CREATE TABLE IF NOT EXISTS nic(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    macaddress VARCHAR(255),
    ipaddress VARCHAR(255),
    ipsubnet VARCHAR(255),
    defaultgateway VARCHAR(255),
    dhcpenabled VARCHAR(255),
    dhcpserver VARCHAR(255),
    dnsserver VARCHAR(255));
''')

# Create osinfo table
etldb.execute('''
CREATE TABLE IF NOT EXISTS osinfo(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    kernel VARCHAR(255),
    version VARCHAR(255),
    buildinfo VARCHAR(255),
    PRIMARY KEY ( computername ));
''')

# Create prefetch table
etldb.execute('''
CREATE TABLE IF NOT EXISTS prefetch(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    length VARCHAR(255),
    directoryname VARCHAR(255),
    creationtime VARCHAR(255),
    lastwritetime VARCHAR(255),
    productversion VARCHAR(255),
    fileversion VARCHAR(255),
    description VARCHAR(255));
''')

# Create processes table
etldb.execute('''
CREATE TABLE IF NOT EXISTS processes(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    processid VARCHAR(255),
    path TEXT,
    commandline TEXT,
    user VARCHAR(255));
''')

# Create servicebinaries table
etldb.execute('''
CREATE TABLE IF NOT EXISTS servicebinaries(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    binarypath VARCHAR(255),
    productname VARCHAR(255),
    filedescription VARCHAR(255),
    companyname VARCHAR(255),
    fileversion VARCHAR(255),
    productversion VARCHAR(255),
    sha1 VARCHAR(255),
    md5 VARCHAR(255));
''')

# Create servicedlls table
etldb.execute('''
CREATE TABLE IF NOT EXISTS servicedlls(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    servicename VARCHAR(255),
    controlset VARCHAR(255),
    servicedll VARCHAR(255));
''')

# Create services table
etldb.execute('''
CREATE TABLE IF NOT EXISTS services(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    controlset VARCHAR(255),
    servicename VARCHAR(255),
    enabled VARCHAR(255),
    loadtype VARCHAR(255),
    state VARCHAR(255),
    imagepath TEXT);
''')

# Create ss table
etldb.execute('''
CREATE TABLE IF NOT EXISTS ss(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    protocol VARCHAR(255),
    l_address VARCHAR(255),
    l_port VARCHAR(255),
    r_address VARCHAR(255),
    r_port VARCHAR(255),
    state VARCHAR(255),
    pid VARCHAR(255));
''')

# Create startups table
etldb.execute('''
CREATE TABLE IF NOT EXISTS startups(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    command TEXT,
    location VARCHAR(255),
    user VARCHAR(255));
''')

# Create tasks table
etldb.execute('''
CREATE TABLE IF NOT EXISTS tasks(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    status VARCHAR(255),
    lastruntime VARCHAR(255),
    nextruntime VARCHAR(255),
    actions TEXT,
    enabled VARCHAR(255),
    author VARCHAR(255),
    description TEXT,
    runas VARCHAR(255),
    created VARCHAR(255));
''')

# Create usbs table
etldb.execute('''
CREATE TABLE IF NOT EXISTS usbs(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    hardwareid VARCHAR(255),
    serial VARCHAR(255),
    class VARCHAR(255),
    service VARCHAR(255));
''')

# Create userhomepaths table
etldb.execute('''
CREATE TABLE IF NOT EXISTS userhomepaths(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    user VARCHAR(255),
    datemodified VARCHAR(255),
    homedir VARCHAR(255));
''')

# Create userallgroups table
etldb.execute('''
CREATE TABLE IF NOT EXISTS userallgroups(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    user VARCHAR(255),
    uid VARCHAR(255),
    gid VARCHAR(255),
    gname VARCHAR(255));
''')

# Create usercron table
etldb.execute('''
CREATE TABLE IF NOT EXISTS usercron(
    computername VARCHAR(255) NOT NULL,
    auditdate VARCHAR(255) NOT NULL,
    min VARCHAR(255),
    hour VARCHAR(255),
    month VARCHAR(255),
    dayofweek VARCHAR(255),
    command TEXT);
''')

log("Done creating database!")

log("Performing Windows ETL...")
####### WINDOWS OPERATIONS #######
# ActiveComms
log("Parsing activecomms")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*activecomms.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO activecomms(computername, auditdate, username, pid, process, servicename, path, servicestarttype, sha1, md5,
            commandline, connected, state, l_address, l_port, r_address, r_port) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            username=VALUES(username),
            pid=VALUES(pid),
            process=VALUES(process), 
            servicename=VALUES(servicename), 
            path=VALUES(path), 
            servicestarttype=VALUES(servicestarttype), 
            sha1=VALUES(sha1), 
            md5=VALUES(md5),
            commandline=VALUES(commandline), 
            connected=VALUES(connected), 
            state=VALUES(state), 
            l_address=VALUES(l_address), 
            l_port=VALUES(l_port), 
            r_address=VALUES(r_address), 
            r_port=VALUES(r_port);
            ''', row)

# All Files
log("Parsing allfiles (this may take a moment)")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allfiles.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allfiles(computername, auditdate, name, length, directory, creationtime, lastwritetime,
            productversion, fileversion, description, sha1, md5) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name),
            length=VALUES(length),
            directory=VALUES(directory), 
            creationtime=VALUES(creationtime), 
            lastwritetime=VALUES(lastwritetime), 
            productversion=VALUES(productversion), 
            fileversion=VALUES(fileversion), 
            description=VALUES(description), 
            sha1=VALUES(sha1), 
            md5=VALUES(md5);
            ''', row)

# All Profiles
log("Parsing allprofiles")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allprofiles.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allprofiles(computername, auditdate, name, length, directory, creationtime, lastwritetime,
            productversion, fileversion, description) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name),
            length=VALUES(length),
            directory=VALUES(directory), 
            creationtime=VALUES(creationtime), 
            lastwritetime=VALUES(lastwritetime), 
            productversion=VALUES(productversion), 
            fileversion=VALUES(fileversion), 
            description=VALUES(description);
            ''', row)

# All Profiles (Registry)
log("Parsing allprofiles_reg")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allprofiles_reg.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allprofiles_reg(computername, auditdate, sid, pschildname, profileimagepath) 
            VALUES(%s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            sid=VALUES(sid),
            pschildname=VALUES(pschildname),
            profileimagepath=VALUES(profileimagepath);
            ''', row)

# All Users
log("Parsing allusers")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allusers.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allusers(computername, auditdate, username, lastlogin, enabled, `groups`) 
            VALUES(%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            username=VALUES(username),
            lastlogin=VALUES(lastlogin),
            enabled=VALUES(enabled),
            `groups`=VALUES(`groups`);
            ''', row)

# All Users (Registry)
log("Parsing allusers_reg")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allusers_reg.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allusers_reg(computername, auditdate, accounttype, caption, domain, sid, fullname, name) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            accounttype=VALUES(accounttype),
            caption=VALUES(caption),
            domain=VALUES(domain),
            sid=VALUES(sid),
            fullname=VALUES(fullname),
            name=VALUES(name);
            ''', row)

# AmCache
log("Parsing hamcache")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*amcache.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO amcache(computername, auditdate, command, path, lastmod) 
            VALUES(%s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            command=VALUES(command),
            path=VALUES(path),
            lastmod=VALUES(lastmod);
            ''', row)

# DNSCache
log("Parsing dnscache")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*dnscache.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO dnscache(computername, auditdate, dns) 
            VALUES(%s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            dns=VALUES(dns);
            ''', row)

# Netstat
log("Parsing netstat")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*netstat.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO netstat(computername, auditdate, protocol, l_address, l_port,
                r_address, r_port, state, pid, process) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            protocol=VALUES(protocol),
            l_address=VALUES(l_address), 
            l_port=VALUES(l_port),
            r_address=VALUES(r_address), 
            r_port=VALUES(r_port), 
            state=VALUES(state),
            pid=VALUES(pid), 
            process=VALUES(process);
            ''', row)

# NIC
log("Parsing nic")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*nic.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO nic(computername, auditdate, description, macaddress, ipaddress,
            ipsubnet, defaultgateway, dhcpenabled, dhcpserver, dnsserver) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            description=VALUES(description),
            macaddress=VALUES(macaddress), 
            ipaddress=VALUES(ipaddress),
            ipsubnet=VALUES(ipsubnet), 
            defaultgateway=VALUES(defaultgateway), 
            dhcpenabled=VALUES(dhcpenabled),
            dhcpserver=VALUES(dhcpserver), 
            dnsserver=VALUES(dnsserver);
            ''', row)

# OS Info
log("Parsing osinfo")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*osinfo.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO osinfo(computername, auditdate, kernel, version, buildinfo) 
            VALUES('{}', '{}', '{}', '{}', '{}')
            ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            kernel=VALUES(kernel),
            version=VALUES(version), 
            buildinfo=VALUES(buildinfo);
            '''.format(row[0], row[1], row[2], row[4], row[6]))
    
# PreFetch
log("Parsing prefetch")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*prefetch.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO prefetch(computername, auditdate, name, length, directoryname,
            creationtime, lastwritetime, productversion, fileversion, description) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name), 
            length=VALUES(length),
            directoryname=VALUES(directoryname), 
            creationtime=VALUES(creationtime),
            lastwritetime=VALUES(lastwritetime), 
            productversion=VALUES(productversion), 
            fileversion=VALUES(fileversion),
            description=VALUES(description);
            ''', row)

# Processes
log("Parsing processes")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*processes.csv')):
    df = pd.read_csv(filename)
    df = df.astype(object)
    df['User'] = "-"
    df = df.where(pd.notnull(df), "-")
    for i, rows in df.iterrows():
        row = rows.values.tolist()
        etldb.execute('''
            INSERT INTO processes(computername, auditdate, name, processid, path, commandline, user) 
            VALUES(%s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name),
            processid=VALUES(processid),
            path=VALUES(path),
            commandline=VALUES(commandline),
            user=VALUES(user);
            ''', row)

# Service Binaries
log("Parsing servicebinaries")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*servicebinaries.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO servicebinaries(computername, auditdate, name, binarypath, productname,
            filedescription, companyname, fileversion, productversion, sha1, md5) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name), 
            binarypath=VALUES(binarypath),
            productname=VALUES(productname), 
            filedescription=VALUES(filedescription),
            companyname=VALUES(companyname), 
            fileversion=VALUES(fileversion),
            productversion=VALUES(productversion), 
            sha1=VALUES(sha1),
            md5=VALUES(md5);
            ''', row)

# Service DLLs
log("Parsing servicedlls")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*servicedlls.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO servicedlls(computername, auditdate, servicename, controlset, servicedll) 
            VALUES(%s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            servicename=VALUES(servicename),
            controlset=VALUES(controlset),
            servicedll=VALUES(servicedll);
            ''', row)

# Services
log("Parsing services")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*services.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO services(computername, auditdate, controlset, 
                servicename, enabled, loadtype, state, imagepath) 
            VALUES('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}') ON DUPLICATE KEY UPDATE
            computername=VALUES(computername),
            auditdate=VALUES(auditdate),
            controlset=VALUES(controlset),
            servicename=VALUES(servicename),
            enabled=VALUES(enabled),
            loadtype=VALUES(loadtype),
            state=VALUES(state),
            imagepath=VALUES(imagepath);
            '''.format(row[0], row[1], row[2], row[3], "-", "-", "-", row[4]))

# Startups
log("Parsing startups")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*startups.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO startups(computername, auditdate, name, command, location, user) 
            VALUES(%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name),
            command=VALUES(command),
            location=VALUES(location),
            user=VALUES(user);
            ''', row)

# Tasks
log("Parsing tasks (this may take a moment)")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*tasks.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO tasks(computername, auditdate, name, status, lastruntime, nextruntime, actions,
            enabled, author, description, runas, created) 
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name),
            status=VALUES(status),
            lastruntime=VALUES(lastruntime), 
            nextruntime=VALUES(nextruntime), 
            actions=VALUES(actions), 
            enabled=VALUES(enabled), 
            author=VALUES(author), 
            description=VALUES(description), 
            runas=VALUES(runas), 
            created=VALUES(created);
            ''', row)

# USBs
log("Parsing usbs")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*usbdev.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO usbs(computername, auditdate, hardwareid, serial, class, service) 
            VALUES(%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            hardwareid=VALUES(hardwareid),
            serial=VALUES(serial),
            class=VALUES(class),
            service=VALUES(service);
            ''', row)

log("Windows ETL completed successfully!")


log("Performing Linux ETL...")
####### LINUX OPERATIONS #######

#Authlog
log("Parsing authlog")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*authlog.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 7:
                etldb.execute('''
                    INSERT INTO authlog(computername, auditdate, date, user, homedir,
                    method, command) 
                    VALUES(%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    date=VALUES(date),
                    user=VALUES(user), 
                    homedir=VALUES(homedir),
                    method=VALUES(method), 
                    command=VALUES(command);
                    ''', row )

# Commands History
log("Parsing commandshistory")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*commandshistory.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 3:
                etldb.execute('''
                    INSERT INTO commandshistory(computername, auditdate, command) 
                    VALUES(%s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    command=VALUES(command);
                    ''', row )

# Cron (system-wide) (Mac)
log("Parsing cron")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-Cron.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 5:
                etldb.execute('''
                    INSERT INTO cron(computername, auditdate, datemodified, command, time) 
                    VALUES(%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    datemodified=VALUES(datemodified),
                    command=VALUES(command),
                    time=VALUES(time);
                    ''', row )

# DNS Resolvers
log("Parsing dnsresolvers")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-dnsresolvers.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 4:
                etldb.execute('''
                    INSERT INTO dnsresolvers(computername, auditdate, dnstype, address) 
                    VALUES(%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    dnstype=VALUES(dnstype),
                    address=VALUES(address);
                    ''', row )

# /etc/passwd
log("Parsing etc_password")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-etc_password.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 7:
                etldb.execute('''
                    INSERT INTO etc_passwd(computername, auditdate, user, uid, gid, homedir, shell) 
                    VALUES(%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    user=VALUES(user),
                    uid=VALUES(uid),
                    gid=VALUES(gid),
                    homedir=VALUES(homedir),
                    shell=VALUES(shell);
                    ''', row )

# LaunchCTL
log("Parsing launchctl")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*launchctl.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 10:
                etldb.execute('''
                    INSERT INTO launchctl(computername, auditdate, service, enabletransactions, limitloadtype,
                    program, timeout, ondemand, machservices, programarguments) 
                    VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    service=VALUES(service),
                    enabletransactions=VALUES(enabletransactions), 
                    limitloadtype=VALUES(limitloadtype),
                    program=VALUES(program), 
                    timeout=VALUES(timeout), 
                    ondemand=VALUES(ondemand),
                    machservices=VALUES(machservices), 
                    programarguments=VALUES(programarguments);
                    ''', row )

# Logon Events
log("Parsing logonevents")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-LogonEvents.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 7:
                etldb.execute('''
                    INSERT INTO logonevents(computername, auditdate, user, logontype, date, time, duration) 
                    VALUES(%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    user=VALUES(user),
                    logontype=VALUES(logontype),
                    date=VALUES(date),
                    time=VALUES(time),
                    duration=VALUES(duration);
                    ''', row )

# MainUserGroups
log("Parsing mainusergroups")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*MainUserGroups.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 6:
                etldb.execute('''
                INSERT INTO mainusergroups(computername, auditdate, user, uid, gid, gname) 
                VALUES(%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
                computername=VALUES(computername), 
                auditdate=VALUES(auditdate), 
                user=VALUES(user),
                uid=VALUES(uid),
                gid=VALUES(gid),
                gname=VALUES(gname);
                ''', row)

# Netstat
log("Parsing netstat")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*netstat.csv'), recursive=True):
    csvfixed = formatIP(filename)
    for (i, rows) in csvfixed.iterrows():
        row = rows.values.tolist()
        if len(row) == 10:
            etldb.execute('''
                INSERT INTO netstat(computername, auditdate, protocol, l_address, l_port,
                r_address, r_port, state, pid, process) 
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                computername=VALUES(computername), 
                auditdate=VALUES(auditdate), 
                protocol=VALUES(protocol),
                l_address=VALUES(l_address), 
                l_port=VALUES(l_port),
                r_address=VALUES(r_address), 
                r_port=VALUES(r_port), 
                state=VALUES(state),
                pid=VALUES(pid), 
                process=VALUES(process);
                ''', row )


# OS Data
log("Parsing os_data")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*os_data.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 5:
                etldb.execute('''
                INSERT INTO osinfo(computername, auditdate, kernel, version, buildinfo) 
                VALUES(%s, %s, %s, %s, %s) 
                ON DUPLICATE KEY UPDATE 
                computername=VALUES(computername), 
                auditdate=VALUES(auditdate), 
                kernel=VALUES(kernel),
                version=VALUES(version), 
                buildinfo=VALUES(buildinfo);
                ''', row)

# Processes
log("Parsing processes")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*processes.csv'), recursive=True):
    df = pd.read_csv(filename)
    df = df.astype(object)
    df = df.replace('%', '%%%%', regex=True)
    for i, rows in df.iterrows():
        row = rows.values.tolist()
        etldb.execute('''
            INSERT INTO processes(computername, auditdate, name, processid, path, commandline, user) 
            VALUES('{}', '{}', '{}', '{}', '{}', '{}', '{}') ON DUPLICATE KEY UPDATE 
            computername=VALUES(computername), 
            auditdate=VALUES(auditdate), 
            name=VALUES(name),
            processid=VALUES(processid),
            path=VALUES(path),
            commandline=VALUES(commandline),
            user=VALUES(user);
            '''.format(row[0], row[1], row[5], row[4], "-", row[6], row[2]))

# Services
log("Parsing services")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*services.csv'), recursive=True):
    with open(filename) as csvfile:
            csvrows = pullRows(csvfile)
            for row in csvrows:
                etldb.execute('''
                INSERT INTO services(computername, auditdate, controlset, 
                    servicename, enabled, loadtype, state, imagepath) 
                VALUES('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}') ON DUPLICATE KEY UPDATE
                computername=VALUES(computername),
                auditdate=VALUES(auditdate),
                controlset=VALUES(controlset),
                servicename=VALUES(servicename),
                enabled=VALUES(enabled),
                loadtype=VALUES(loadtype),
                state=VALUES(state),
                imagepath=VALUES(imagepath);
                '''.format(row[0], row[1], "-", row[2], row[3], row[4], row[5], "-"))

# # SS
# log("Parsing ss")
# for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-ss.csv'), recursive=True):
#     csvfixed = formatIP(filename)
#     csvfixed.update('"' + df[['PID']].astype(str) + '"')
#     for (i, rows) in csvfixed.iterrows():
#         row = rows.values.tolist()
#         if len(row) == 9:
#             etldb.execute('''
#                 INSERT INTO ss(computername, auditdate, protocol, l_address, l_port,
#                 r_address, r_port, state, pid) 
#                 VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
#                 ON DUPLICATE KEY UPDATE 
#                 computername=VALUES(computername), 
#                 auditdate=VALUES(auditdate), 
#                 protocol=VALUES(protocol),
#                 l_address=VALUES(l_address), 
#                 l_port=VALUES(l_port),
#                 r_address=VALUES(r_address), 
#                 r_port=VALUES(r_port), 
#                 state=VALUES(state),
#                 pid=VALUES(pid);
#                 ''', row )

# Startups
log("Parsing startupservice")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*StartupService.csv'), recursive=True):
    print(filename)
    with open(filename) as csvfile:
            csvrows = pullRows(csvfile)
            for row in csvrows:
                if len(row) == 6:
                    etldb.execute('''
                    INSERT INTO startups(computername, auditdate, name, command, location, user) 
                    VALUES('{}', '{}', '{}', '{}', '{}', '{}') ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    name=VALUES(name),
                    command=VALUES(command),
                    location=VALUES(location),
                    user=VALUES(user);
                    '''.format(row[0], row[1], row[5], "-", "-", row[2]))

# UserHomePaths
log("Parsing userhomepaths")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*UserHomePaths.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 5:
                etldb.execute('''
                INSERT INTO userhomepaths(computername, auditdate, user, datemodified, homedir) 
                VALUES(%s, %s, %s, %s, %s) 
                ON DUPLICATE KEY UPDATE 
                computername=VALUES(computername), 
                auditdate=VALUES(auditdate), 
                user=VALUES(user),
                datemodified=VALUES(datemodified), 
                homedir=VALUES(homedir);
                ''', row)

# UserAllGroups (Mac)
log("Parsing userallgroups")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*UserAllGroups.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 6:
                etldb.execute('''
                INSERT INTO userallgroups(computername, auditdate, user, uid, gid, gname) 
                VALUES(%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE 
                computername=VALUES(computername), 
                auditdate=VALUES(auditdate), 
                user=VALUES(user),
                uid=VALUES(uid),
                gid=VALUES(gid),
                gname=VALUES(gname);
                ''', row)

# UserCron (Mac)
log("Parsing logonevents")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*UserCron.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 7:
                etldb.execute('''
                    INSERT INTO usercron(computername, auditdate, min, hour, month, dayofweek, command) 
                    VALUES(%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    computername=VALUES(computername), 
                    auditdate=VALUES(auditdate), 
                    min=VALUES(min),
                    hour=VALUES(hour),
                    month=VALUES(month),
                    dayofweek=VALUES(dayofweek),
                    command=VALUES(command);
                    ''', row )

log("Done!")
