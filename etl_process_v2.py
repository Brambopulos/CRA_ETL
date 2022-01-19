# etl_process.py v1.2
# Modified by Brandon Pimentel
# Current Revision 011922

import argparse
import csv
import glob
import io
import os
import pandas as pd
import re
import sqlalchemy
import sqlite3
import tarfile
import zipfile

cwd = os.getcwd()

parser = argparse.ArgumentParser(description='ETL Program; Brandon Pimentel 011922')
parser.add_argument("-v", "--verbose", help="Prints verbose program execution information", action="store_true")
parser.add_argument("-l", "--location", help="MySQL Database Location (default: ./etl.db)", default="etl.db")
args = parser.parse_args()

def log(s):
    if args.verbose:
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

def formatSS(csvfile):
    with open(csvfile, 'r') as f:
        fo = io.StringIO()
        data = f.readlines()
        fo.writelines(re.sub('users*pid', '', line) for line in data)
        fo.seek(0)

    col_names=['Computername', 'AuditDate', 'Protocol', 'LocalAddress', 'RemoteAddress', 'State', 'PID']
    df = pd.read_csv(fo, names=col_names, on_bad_lines='skip')
    df.insert(4, 'LocalPort', None)
    df.insert(5, 'RemotePort', None)
    df = df.astype(object)
    for (i, row) in df.iterrows():
        lAddress = str(df.at[i, 'LocalAddress'])
        rAddress = str(df.at[i, 'RemoteAddress'])
        if ":" in lAddress:
            df.at[i, 'LocalAddress'] = lAddress.rsplit(":")[0]
            df.at[i, 'LocalPort'] = lAddress.rsplit(":")[1]
        if ":" in rAddress:
            df.at[i, 'RemoteAddress'] = rAddress.rsplit(":")[1]
            df.at[i, 'RemotePort'] = rAddress.rsplit(":")[1]


    df = df.where(pd.notnull(df), "-")
    return df

def pullRows(csvfile):
    reader = csv.reader(csvfile, delimiter=',')
    next(reader)
    csvrows = list(reader)
    return csvrows


####### INITIALIZATION #######

# Detect files currently in dir
files = os.listdir(".")

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
etldb = sqlalchemy.create_engine("sqlite:///{}".format(args.location))

log("Creating database...")
# Create ETL database
# etldb.execute("CREATE DATABASE IF NOT EXISTS {}".format(args.name))
# etldb.execute("USE {}".format(args.name))

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
            INSERT INTO activecomms
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, 
            ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# All Files
log("Parsing allfiles (this may take some time)")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allfiles.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allfiles
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# All Profiles
log("Parsing allprofiles")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allprofiles.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allprofiles
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# All Profiles (Registry)
log("Parsing allprofiles_reg")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allprofiles_reg.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allprofiles_reg
            VALUES(?, ?, ?, ?, ?);
            ''', row)

# All Users
log("Parsing allusers")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allusers.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allusers
            VALUES(?, ?, ?, ?, ?, ?);
            ''', row)

# All Users (Registry)
log("Parsing allusers_reg")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*allusers_reg.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO allusers_reg
            VALUES(?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# AmCache
log("Parsing hamcache")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*amcache.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO amcache
            VALUES(?, ?, ?, ?, ?);
            ''', row)

# DNSCache
log("Parsing dnscache")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*dnscache.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO dnscache
            VALUES(?, ?, ?);
            ''', row)

# Netstat
log("Parsing netstat (this may take some time)")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*netstat.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO netstat
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# NIC
log("Parsing nic")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*nic.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO nic
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# OS Info
log("Parsing osinfo")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*osinfo.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            REPLACE INTO osinfo
            VALUES(?, ?, ?, ?, ?);
            ''', row[0], row[1], row[2], row[4], row[6])
    
# PreFetch
log("Parsing prefetch")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*prefetch.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO prefetch
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
            INSERT INTO processes
            VALUES(?, ?, ?, ?, ?, ?, ?);
            ''', row)

# Service Binaries
log("Parsing servicebinaries")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*servicebinaries.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO servicebinaries
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# Service DLLs
log("Parsing servicedlls")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*servicedlls.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO servicedlls
            VALUES(?, ?, ?, ?, ?);
            ''', row)

# Services
log("Parsing services (this may take some time)")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*services.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO services
            VALUES(?, ?, ?, ?, ?, ?, ?, ?);
            ''', row[0], row[1], row[2], row[3], "-", "-", "-", row[4])

# Startups
log("Parsing startups")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*startups.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO startups
            VALUES(?, ?, ?, ?, ?, ?);
            ''', row)

# Tasks
log("Parsing tasks (this may take a moment)")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*tasks.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO tasks
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', row)

# USBs
log("Parsing usbs")
for filename in glob.glob(os.path.join(cwd + '/win_temp/*usbdev.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            etldb.execute('''
            INSERT INTO usbs 
            VALUES(?, ?, ?, ?, ?, ?);
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
            if len(row) >= 7:
                etldb.execute('''
                    INSERT INTO authlog
                    VALUES(?, ?, ?, ?, ?, ?, ?);
                    ''', row[:7])

# Commands History
log("Parsing commandshistory (this may take some time)")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*commandshistory.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) == 3:
                etldb.execute('''
                    INSERT INTO commandshistory
                    VALUES(?, ?, ?);
                    ''', row[:3] )

# Cron (system-wide) (Mac)
log("Parsing cron")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-Cron.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 5:
                etldb.execute('''
                    INSERT INTO cron
                    VALUES(?, ?, ?, ?, ?);
                    ''', row[:5] )

# DNS Resolvers
log("Parsing dnsresolvers")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-dnsresolvers.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 4:
                etldb.execute('''
                    INSERT INTO dnsresolvers
                    VALUES(?, ?, ?, ?);
                    ''', row[:4] )

# /etc/passwd
log("Parsing etc_password")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-etc_password.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 7:
                etldb.execute('''
                    INSERT INTO etc_passwd
                    VALUES(?, ?, ?, ?, ?, ?, ?);
                    ''', row[:7] )

# LaunchCTL
log("Parsing launchctl")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*launchctl.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 10:
                etldb.execute('''
                    INSERT INTO launchctl
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    ''', row[:10] )

# Logon Events
log("Parsing logonevents")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-LogonEvents.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 7:
                etldb.execute('''
                    INSERT INTO logonevents
                    VALUES(?, ?, ?, ?, ?, ?, ?);
                    ''', row[:7] )

# MainUserGroups
log("Parsing mainusergroups")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*MainUserGroups.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 6:
                etldb.execute('''
                INSERT INTO mainusergroups
                VALUES(?, ?, ?, ?, ?, ?);
                ''', row[:6])

# Netstat
log("Parsing netstat (this may take some time)")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*netstat.csv'), recursive=True):
    csvfixed = formatIP(filename)
    for (i, rows) in csvfixed.iterrows():
        row = rows.values.tolist()
        if len(row) >= 10:
            etldb.execute('''
                INSERT INTO netstat
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                ''', row[:10] )


# OS Data
log("Parsing os_data")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*os_data.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 5:
                etldb.execute('''
                INSERT INTO osinfo
                VALUES(?, ?, ?, ?, ?);
                ''', row[:5])

# Processes
log("Parsing processes")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*processes.csv'), recursive=True):
    df = pd.read_csv(filename)
    df = df.astype(object)
    df = df.replace('%', '%%%%', regex=True)
    for i, rows in df.iterrows():
        row = rows.values.tolist()
        etldb.execute('''
            INSERT INTO processes 
            VALUES(?, ?, ?, ?, ?, ?, ?);
            ''', row[0], row[1], row[5], row[4], "-", row[6], row[2])

# Services
log("Parsing services")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*services.csv'), recursive=True):
    with open(filename) as csvfile:
            csvrows = pullRows(csvfile)
            for row in csvrows:
                etldb.execute('''
                INSERT INTO services
                VALUES(?, ?, ?, ?, ?, ?, ?, ?);
                ''', row[0], row[1], "-", row[2], row[3], row[4], row[5], "-")

# SS
log("Parsing ss")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*-ss.csv'), recursive=True):
    csvfixed = formatSS(filename)
    csvfixed.drop(index=csvfixed.index[0], axis=0, inplace=True)
    for (i, rows) in csvfixed.iterrows():
        row = rows.values.tolist()
        if len(row) == 9:
            etldb.execute('''
                INSERT INTO ss
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);
                ''', row[:9] )

# Startups
log("Parsing startupservice")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*StartupService.csv'), recursive=True):
    with open(filename) as csvfile:
            csvrows = pullRows(csvfile)
            for row in csvrows:
                if len(row) >= 6:
                    etldb.execute('''
                    INSERT INTO startups
                    VALUES(?, ?, ?, ?, ?, ?);
                    ''', row[0], row[1], row[5], "-", "-", row[2])

# UserHomePaths
log("Parsing userhomepaths")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*UserHomePaths.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 5:
                etldb.execute('''
                INSERT INTO userhomepaths
                VALUES(?, ?, ?, ?, ?);
                ''', row[:5])

# UserAllGroups (Mac)
log("Parsing userallgroups")
for filename in glob.glob(os.path.join(cwd + '/lin_temp/**/*UserAllGroups.csv')):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 6:
                etldb.execute('''
                INSERT INTO userallgroups
                VALUES(?, ?, ?, ?, ?, ?);
                ''', row[:6])

# UserCron (Mac)
log("Parsing logonevents")
for filename in glob.iglob(os.path.join(cwd + '/lin_temp/**/*UserCron.csv'), recursive=True):
    with open(filename) as csvfile:
        csvrows = pullRows(csvfile)
        for row in csvrows:
            if len(row) >= 7:
                etldb.execute('''
                    INSERT INTO usercron
                    VALUES(?, ?, ?, ?, ?, ?, ?);
                    ''', row[:7] )

log("Done!")
