"""
Monitor: a login activity monitor to stream log data from a csv, and identify suspicious activity.

Contact: ahadsheriff@gmail.com
"""

import sys
import csv
import time
import hashlib
import argparse
from user_agents import parse


class Monitor:

    def __init__(self, filename: str):

        # Initialize our data structure to collect statistics, and monitoring data.
        self.login_stats = {
            "total_severe": 0,
            "total_warning": 0,
            "brute_force_users": {},
            "compromised_users": {},
            "deny_list": {},
            "watch_list": {},
            "success": {
                "total": 0,
                "users": {},
            },
            "fail": {
                "total": 0,
                "users": {},
            }
        }
        self.stream_logs(filename)

    def stream_logs(self, filename: str):
        # Streams data in from a file one line per second
        # Every 15-seconds, the function will call get_stats() to return monitoring statistics.

        timer = 0
        traffic = csv.DictReader(open(filename))

        for event in traffic:
            time.sleep(1)
            self.process_data(event)
            timer += 1

            if timer % 15 == 0:
                self.get_stats()

    def process_data(self, event: list):
        # Takes event data from the log file, and breaks it down into relevant bits.
        # Relevant data includes userid, ip, browser, os, and device.
        # This data is then hashed to create a unique fingerprint for the event.
        # Based on whether the login was successful or not, the function then makes a
        #   call to another function to add events to the data structure.

        userid = event['userid']
        ip = event['ip']
        user_agent = parse(event['useragent'])
        browser = user_agent.browser.family
        os = user_agent.os.family
        device = user_agent.device.family

        # Generate md5 hash of our metadata to generate a unique id for the login agent
        event_data = userid + ip + browser + os + device
        event_fingerprint = hashlib.md5(event_data.encode())
        event_fingerprint_id = event_fingerprint.hexdigest()

        if event['status_code'] == '200':
            self.login_success(
                userid=userid, fingerprint_id=event_fingerprint_id)
        else:
            self.login_fail(userid=userid, fingerprint_id=event_fingerprint_id)

    def login_success(self, userid: str, fingerprint_id):
        # If the login is a success, print info to console and add the event to our data structure.
        # This function also checks to see if the number of successful logins for this user is
        #   abnormal and will call another function to check if it is an anomaly.

        print("user " + "'" + userid + "'" +
              " signed in successfully from origin", fingerprint_id)

        if userid not in self.login_stats["success"]["users"]:
            self.login_stats["success"]["users"][userid] = {
                "fingerprints": [fingerprint_id], "attempts": 0}

        else:
            self.login_stats["success"]["users"][userid]["fingerprints"].append(
                fingerprint_id)

        self.login_stats["success"]["users"][userid]["attempts"] += 1

        if self.login_stats["success"]["users"][userid]["attempts"] > 3:
            self.successful_login_anomalies(
                userid, self.login_stats["success"]["users"][userid]["attempts"])

        self.login_stats["success"]["total"] += 1

    def login_fail(self, userid: str, fingerprint_id: str):
        # If the login is a fail, print info to console and add the event to our data structure.
        # This function also checks to see if the number of failed logins for this user is
        #   abnormal and will call another function to check if it is an anomaly.

        print("user " + "'" + userid + "'" +
              " failed to login from origin", fingerprint_id)

        if userid not in self.login_stats["fail"]["users"]:
            self.login_stats["fail"]["users"][userid] = {
                "fingerprints": [fingerprint_id], "attempts": 0}

        else:
            self.login_stats["fail"]["users"][userid]["fingerprints"].append(
                fingerprint_id)

        self.login_stats["fail"]["users"][userid]["attempts"] += 1

        if self.login_stats["fail"]["users"][userid]["attempts"] > 1:
            self.failed_login_anomalies(
                userid, self.login_stats["fail"]["users"][userid]["attempts"])

        self.login_stats["fail"]["total"] += 1

    def failed_login_anomalies(self, userid: str, count: int):
        # This function checks to see if the failed login event is an anomaly.
        # We determine severity and predict the type of attack based
        #   on the number of failed events, and whether the
        #   activity is coming from several origins, or the same one.
        # This function also adds dangerous fingerprints to a deny list or watch list
        #   based on severity.

        print()
        print("----------------------------------------------------------------")
        print("ALERT")
        print("----------------------------------------------------------------")

        origins = self.login_stats["fail"]["users"][userid]["fingerprints"]
        same_origin = True

        for origin in origins:
            if origins[0] != origin:
                same_origin = False
                break

        # Escalate WARNING to SEVERE after more than 5 failed attempts
        if count < 5:
            if same_origin:
                print(
                    "WARNING: POSSIBLE BRUTE FORCE LOGIN ATTEMPT FOR ACCOUNT -", userid)
                print("MESSAGE: Multiple failed login attempts.")
                print(
                    "ACTION: Notify user of suspicious activity, and suggest password reset.\n")
                print("Adding the following origin to watchlist:", origins[0])
                self.login_stats["total_warning"] += 1

            else:
                print(
                    "WARNING: POSSIBLE BRUTE FORCE LOGIN ATTEMPT FOR ACCOUNT -", userid)
                print("MESSAGE: Multiple failed login attempts from many origins.")
                print(
                    "ACTION: Ask user to verify login attempt, and suggest password reset.\n")
                print("Adding", count, "origins to watchlist.")
                self.login_stats["total_warning"] += 1

            # Populate brute force watchlist
            for i in origins:
                if i not in self.login_stats["watch_list"]:
                    self.login_stats["watch_list"][i] = 1
                else:
                    self.login_stats["watch_list"][i] += 1
        else:
            if same_origin:
                print("SEVERE: POSSIBLE BRUTE FORCE LOGIN ATTEMPT FOR ACCOUNT -", userid)
                print("MESSAGE: Multiple failed login attempts from same origin.")
                print(
                    "ACTION: Notify user of suspicious activity, and require password reset.\n")
                print("Denying all requests from origin:", origins[0])
                self.login_stats["total_severe"] += 1

            else:
                print("SEVERE: POSSIBLE BRUTE FORCE LOGIN ATTEMPT FOR ACCOUNT -", userid)
                print("MESSAGE: Multiple failed login attempts from many origins.")
                print(
                    "ACTION: Notify user of suspicious activity, and require password reset.\n")
                print("Denying all requests from", count, "origins.")
                self.login_stats["total_severe"] += 1

            # Populate brute force deny list
            for i in origins:
                if i not in self.login_stats["deny_list"]:
                    self.login_stats["deny_list"][i] = 1

        # map brute force targets in a dict with key = userid and val = num of times targeted
        if userid not in self.login_stats["brute_force_users"]:
            self.login_stats["brute_force_users"][userid] = 1
        else:
            self.login_stats["brute_force_users"][userid] += 1

        print()

    def successful_login_anomalies(self, userid: str, count: int):
        # This function checks to see if the successful login event is an anomaly.
        # We determine severity and predict the type of attack based on the number
        #   of failed events, and whether the activity is coming from several
        #   origins, or the same one.
        # This function also adds dangerous fingerprints to a deny list or watch list
        #   based on severity.

        print()
        print("----------------------------------------------------------------")
        print("ALERT")
        print("----------------------------------------------------------------")

        origins = self.login_stats["success"]["users"][userid]["fingerprints"]
        same_origin = True

        for origin in origins:
            if origins[0] != origin:
                same_origin = False
                break

        # Escalate WARNING to SEVERE after more than 3 successful attempts
        if count < 3:
            if same_origin == False:
                print("WARNING: ACCOUNT " + "'" +
                      userid + "'" + " MAY BE COMPROMISED.")
                print("MESSAGE: Login from unrecognized device.")
                print(
                    "ACTION: Notify user of suspicious account login, and ask to verify if it was them.\n")
                print("Adding the following origin to watchlist:", origins[0])
                self.login_stats["total_warning"] += 1

                # populate watchlist with key = fingerprint and val = num of targets
                for i in origins:
                    if i not in self.login_stats["watch_list"]:
                        self.login_stats["watch_list"][i] = 1
                    else:
                        self.login_stats["watch_list"][i] += 1

        else:
            if same_origin == False:
                print("SEVERE: ACCOUNT " + "'" + userid +
                      "'" + " MAY BE COMPROMISED.")
                print("MESSAGE: Multiple successful logins from many origins.")
                print(
                    "ACTION: Notify user of suspicious account login, and require password reset.\n")
                print("Denying all requests from", count, "origins.")
                self.login_stats["total_severe"] += 1

            else:
                print("SEVERE: ACCOUNT " + "'" + userid +
                      "'" + " MAY BE COMPROMISED.")
                print("MESSAGE: Multiple successful logins from single origin.")
                print(
                    "ACTION: Notify user of suspicious account login, and require password reset.\n")
                print("Denying all requests from origin:", origins[0])
                self.login_stats["total_severe"] += 1

            # populate denylist in a dict with key = fingerprint and val = num of targets
            for i in origins:
                if i not in self.login_stats["deny_list"]:
                    self.login_stats["deny_list"][i] = 1
                else:
                    self.login_stats["deny_list"][i] += 1

        # map compromised targets in a dict with key = userid and val = num of times targeted
        if userid not in self.login_stats["compromised_users"]:
            self.login_stats["compromised_users"][userid] = 1
        else:
            self.login_stats["compromised_users"][userid] += 1

        print()

    def get_stats(self):
        # Prints relevant statistics to the console. This function is called every 15 secs.

        print()
        print("----------------------------------------------------------------")
        print("STATISTICS")
        print("----------------------------------------------------------------")
        print("Total Logins: ", self.login_stats["fail"]
              ["total"] + self.login_stats["success"]["total"])
        print("Total Successful Logins: ",
              self.login_stats["success"]["total"])
        print("Total Failed Logins: ", self.login_stats["fail"]["total"])
        print("Total Anomalies Detected: ",
              self.login_stats["total_severe"] + self.login_stats["total_warning"])
        print("Total Severe Alerts: ", self.login_stats["total_severe"])
        print("Total Warning Alerts: ", self.login_stats["total_warning"])
        print("Number of Possible Brute Force Attacks: ", len(
            list(self.login_stats["brute_force_users"].keys())))
        print("Possible Brute Force Targets: ", list(
            self.login_stats["brute_force_users"].keys()))
        print("Number of Possible Compromised Accounts: ", len(
            list(self.login_stats["compromised_users"].keys())))
        print("Possible Compromised Accounts: ", list(
            self.login_stats["compromised_users"].keys()))
        print()

    def get_suspicious_fingerprints(self):
        # This function will print out the contents of the deny list and watch list.

        print("SUSPICIOUS SOURCES:")
        print("Deny List:\n", list(monitor.login_stats["deny_list"].keys()))
        print()
        print("Watch List:\n", list(monitor.login_stats["watch_list"].keys()))
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f", type=str, required=True)
    args = parser.parse_args()

    filename = args.file
    monitor = Monitor(filename)

    # uncomment to see deny/watch list data
    # monitor.get_suspicious_fingerprints()
