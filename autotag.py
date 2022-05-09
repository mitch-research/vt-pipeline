#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Code development started with forking the following repository:
https://github.com/fr0gger/vthunting

Usage:
python antotag.py [options]

Install:
pip install requests slackclient==1.0.7 pymsteams
"""
import requests
import json
import datetime as dt
import re
# import smtplib
import getopt
import sys
import sqlite3
# import pymsteams
import time
import os
import os.path
import shutil
from requests import *
from datetime import datetime, timedelta
import yara
# import glob
# import hashlib
import configparser

# from slackclient import SlackClient

# authorship information
__author__ = "J0e9 Ch3n"
__team__ = "Threat intelligence tool"
__version__ = "1.0"
__status__ = "Release 1.0"

current_path = os.path.dirname(os.path.realpath(__file__))

number_of_result = ""  # fetch this many notifications per API request. 10 by default, 40 max
max_notifications = None  # fetch this many notifications in total
vturl = 'https://www.virustotal.com/api/v3/intelligence/hunting_notifications'
vtdownload = "https://www.virustotal.com/vtapi/v2/file/download"
data_tmp = current_path + "/data_tmp/"
data_archive = current_path + "/data_archive/"

# Log report
report_log_file = current_path + "/report.log"

# Missing log file location
missing_log_file = current_path + "/missing.log"

# Errors log file location
errors_log_file = current_path + "/errors.log"

# Create an APP on gmail if you are using double authentication https://support.google.com/accounts/answer/185833
smtp_serv = ""
smtp_port = ""
gmail_login = ""
gmail_pass = ""  # pass from APP
gmail_dest = ""

# Slack Bot config
SLACK_BOT_TOKEN = ""
SLACK_EMOJI = ":rooster:"
SLACK_BOT_NAME = ""
SLACK_CHANNEL = ""

# -----------------------------------------------------------------------

# Global Variable
now = dt.datetime.now()
regex = "[A-Fa-f0-9]{64}"  # Detect SHA256
end_message = "End of report"
database_connection = sqlite3.connect('antotag.sqlite')


# Print help
def usage():
    print("usage: antotag.py -s [OPTION]")
    print('''   
    -h, --help                   Print this help
    -s, --source                 Choose a data source (livehunt, search)

Example: Query your VirusTotal livehunt notifications (requires VT subscription)
    antotag.py -s livehunt
Example: Query your VirusTotal column syntax search (requires VT subscription)
    antotag.py -s search
    ''')


# Directory structure
def create_dirs(data_tmp, data_archive):
    directories = [data_tmp, data_archive]
    for directory in directories:
        try:
            os.mkdir(directory)
        except OSError:
            print("Creation of the directory " + directory + " failed")


'''
# Posting to a Slack channel
def send_slack_report(report):
    sc = SlackClient(SLACK_BOT_TOKEN)
    if sc.rtm_connect(with_team_state=False):
        sc.api_call(
            "chat.postMessage",
            icon_emoji=SLACK_EMOJI,
            username=SLACK_BOT_NAME,
            channel=SLACK_CHANNEL,
            text=report
        )
        print("[*] Report has been sent to your Slack channel!")

    else:
        print("[!] Connection failed! Exception traceback printed above.")
        sys.exit()
'''
'''
# Send email report
def send_email_report(report):
    from_email = gmail_login
    to_email = [gmail_dest]  # ['me@gmail.com', 'bill@gmail.com']
    subject = "Virus Total Hunting Report - " + str(now)
    text = report
    message = 'Subject: {}\n\n{}'.format(subject, text)

    try:
        server = smtplib.SMTP_SSL(smtp_serv, smtp_port)
        server.ehlo()
        server.login(from_email, gmail_pass)
        # Send the mail

        server.sendmail(from_email, to_email, message)
        server.quit()
        print("[*] Report have been sent to your email!")
    except smtplib.SMTPException as e:
        print("[!] SMTP error: " + str(e))
        sys.exit()
'''


def initialize_autotag_database():
    autotag_sql = """
    CREATE TABLE IF NOT EXISTS autotag_db (
    sha256 text constraint autotag_db_pk primary key,
    rule_name text,
    notification_date int
    );"""
    try:
        database_connection.execute(autotag_sql)
    except Exception as e:
        print("[!] Error with creating the table in the SQLite3 database: " + str(e))
        sys.exit()
    finally:
        database_connection.commit()


def sha256_was_seen_before(sha256):
    return bool(database_connection.execute('SELECT EXISTS ( SELECT sha256 FROM autotag_db WHERE sha256 = ?)',
                                            [str(sha256)]).fetchone()[0])


def update_autotag_db(sha256, rule_name, notification_date):
    if not sha256_was_seen_before(sha256):
        try:
            database_connection.execute(
                'INSERT INTO autotag_db (sha256, rule_name, notification_date) values (?, ?, ?)',
                [str(sha256), str(rule_name), int(notification_date)])
        except Exception as e:
            print("[!] Error updating the SQLite3 database: " + str(e))
            sys.exit()
        finally:
            database_connection.commit()


# VT search (detected by AVs)
def vt_intelligence(VT_key):
    if VT_key is None:
        raise Exception("You must provide a valid VT API key")

    notifications = []
    delta = datetime.now() - timedelta(days=1)
    first_seen = 'fs:{}+'.format(delta.strftime("%Y-%m-%dT%H:%M:%S"))
    query = '(engines:"Shadowpad" OR engines:"POPPINGBEE" OR engines:"Win32/Shadowpad") AND (type:pedll OR type:peexe) AND ' + first_seen
    limit = '100'
    params = {'query': query, 'limit': limit}
    response = requests.get('https://www.virustotal.com/api/v3/intelligence/search',
                            params=params,
                            headers={'x-apikey': VT_key,
                                     'Accept': 'application/json'})
    result = json.loads(response.text)

    for json_row in result['data']:
        notifications.append(json_row)

    # Start report
    report = [""]
    # Update match date
    day = now.strftime("%d")
    month = now.strftime("%m")
    year = now.strftime("%Y")
    date = month + "/" + day + "/" + year

    for json_row in notifications:
        sha256 = json_row["attributes"]["sha256"]
        malicious = json_row["attributes"]["last_analysis_stats"]["malicious"]
        undetected = json_row["attributes"]["last_analysis_stats"]["undetected"]
        total_engines = malicious + undetected
        if not sha256_was_seen_before(sha256):
            # Download file to disk
            download_file_vt(VT_key, sha256, data_tmp)
            # Update database
            update_autotag_db(sha256, 'VT search', int(time.time()))
            report.append("Rule name: " + "VT (" + str(malicious) + "/" + str(total_engines) + ")")
            report.append("Match date: " + date)
            report.append("SHA256: " + str(sha256))
            report.append("-------------------------------------------------------------------------------------")
            # Move file
            if os.path.isfile(data_tmp + sha256):
                shutil.move(data_tmp + sha256, data_archive + sha256)

        report.append(end_message)
    report = ("\n".join(report))
    return report


# VT live hunt notifications (detected by YARA rules)
def api_request(VT_key):
    if VT_key is None:
        raise Exception("You must provide a valid VT API key")

    print('Checking VirusTotal Livehunt API for new notifications, please wait...')
    fetch_more_notifications = True
    limit = 30
    notifications = []
    new_entry = False
    malware_found_count = 0

    if number_of_result:
        limit = int(number_of_result)
    if max_notifications and max_notifications < limit:
        limit = max_notifications

    # add yara filter
    params = {
        'limit': limit,
        'filter': 'shadowpad'
    }

    headers = {"x-apikey": VT_key}

    while fetch_more_notifications:
        response = requests.get(vturl, params=params, headers=headers)
        result = json.loads(response.text)


        for json_row in result['data']:
            notifications.append(json_row)

        # Response has cursor, more notifications can be fetched
        if 'cursor' in result['meta'].keys():
            params.update({'cursor': result['meta']['cursor']})

            if max_notifications:
                # reached limit, stop fetching more notifications
                if len(notifications) == max_notifications:
                    fetch_more_notifications = False
                # limit amount of notifications to fetch on next iteration, to reach max
                elif len(notifications) + limit > max_notifications:
                    params.update({'limit': max_notifications - len(notifications)})
        else:
            fetch_more_notifications = False

    # Start report
    report = ["-------------------------------------------------------------------------------------"]

    for json_row in notifications:
        rule_name = json_row["attributes"]["rule_name"]
        date = json_row["attributes"]["date"]
        tags = json_row["attributes"]["tags"]
        snippet = json_row["attributes"]["snippet"]
        sha256 = re.search(regex, str(tags)).group()
        tags.remove(sha256)

        # Only continue if hash was not seen before
        if not sha256_was_seen_before(sha256):
            new_entry = True
            # Call function to download file from VT
            download_file_vt(VT_key, sha256, data_tmp)
            # Update database
            update_autotag_db(sha256, rule_name, date)
            malware_found_count += 1
            report.append("Rule name: " + rule_name)
            report.append("Match date: " + datetime.utcfromtimestamp(date).strftime('%m/%d/%Y'))
            report.append("SHA256: " + str(sha256))
            # report.append("Tags: " + str([str(tags) for tags in tags]).replace("'", ""))
            # report.append("Snippet: " + snippet)
            report.append("-------------------------------------------------------------------------------------")

        # Move file
        if os.path.isfile(data_tmp + sha256):
            shutil.move(data_tmp + sha256, data_archive + sha256)

    if new_entry:
        report.append("\nSTATS:")
        report.append("new malware found: " + str(malware_found_count) + "\n")  # TBD

    if not new_entry:
        print("No new entry!")

        report.append(end_message)
    report = ("\n".join(report))
    return report, notifications


table = []


def mycallback(data):
    print(data)
    table.append(data)
    return yara.CALLBACK_CONTINUE


# Download file from VT
def download_file_vt(VT_key, sha256, data_tmp):
    r = requests.get(vtdownload, params={"apikey": VT_key, "hash": sha256})
    with open(data_tmp + sha256, "wb") as f:
        f.write(r.content)


def main(argv):
    print(__team__ + " | " + __author__ + "\n")
    # Create directories
    if not os.path.isdir(data_tmp):
        create_dirs(data_tmp, data_archive)
    # Read config file
    try:
        config = configparser.ConfigParser()
        config.read("config.ini")
        VT_key = config.get("VirusTotal", "api_key")
    except Exception as e:
        print("[!] Unable to read the config.ini file: {}".format(str(e)))

    try:
        opts, args = getopt.getopt(argv, "hs:o:", ["source=", "output="])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-s", "--source"):
            if arg == "livehunt":
                # VirusTotal as source
                initialize_autotag_database()
                try:
                    report, result_json = api_request(VT_key)
                    print(report)
                except(ConnectionError, ConnectTimeout, KeyError) as e:
                    print("[!] Error with the VT API: " + str(e))
                    sys.exit()
                database_connection.close()
            elif arg == "search":
                # Local folder as source
                initialize_autotag_database()
                try:
                    report = vt_intelligence(VT_key)
                    print(report)
                except(ConnectionError, ConnectTimeout, KeyError) as e:
                    print("[!] Error with the VT API: " + str(e))
                    sys.exit()
                database_connection.close()
            else:
                usage()
                sys.exit()


if __name__ == '__main__':
    main(sys.argv[1:])
