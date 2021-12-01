#!/bin/python3

import pdb
import paramiko
import argparse
import logging
import json
import re # may need this for looking at inputfrom shell
import ipaddress
import getpass
import pathlib
import datetime
from socket import gethostbyname as getipaddress

parser = argparse.ArgumentParser(description="an ssh key inventory script. Returns a folder of json files showing which ssh public keys are associated with which users on which hosts.  Best viewed when imported into Elasticsearch. This script currently only works for Linux hosts")
parser.add_argument("-t", "--targetfile", default=pathlib.Path.cwd().joinpath("targets"), type=pathlib.Path, action="store", help="the path to a textfile with all ip or hostnames to scan. One hostname or IP per line.  the default targetfile is in the current working directory and named targets")
parser.add_argument("-s", "--sudoall", action="store_true", help="use the same sudo password for all hosts, the default is to prompt for each host")
parser.add_argument("-u", "--user", required=True, help="the user to login to the remote system, must have sudo privs")
parser.add_argument("-v", "--verbosity", action="count", default=1, help="adjust output verbosity")
args = parser.parse_args()

if args.verbosity >= 3:
    logging.basicConfig(filename='ssh-creds.log', encoding='utf-8',
            format='%(asctime)s - %(levelname)s:%(message)s', level=logging.DEBUG)
elif args.verbosity >= 2:
    logging.basicConfig(filename='ssh-creds.log', encoding='utf-8',
            format='%(asctime)s - %(levelname)s:%(message)s', level=logging.INFO)
elif args.verbosity >= 1:
    logging.basicConfig(filename='ssh-creds.log', encoding='utf-8',
            format='%(asctime)s - %(levelname)s:%(message)s', level=logging.WARNING)
elif args.verbosity >= 0:
    logging.basicConfig(filename='ssh-creds.log', encoding='utf-8',
            format='%(asctime)s - %(levelname)s:%(message)s', level=logging.ERROR)

logging.info(f'logging level selected {args.verbosity}')

if args.sudoall:
    global_sudo = getpass.getpass(prompt='global sudo password:', stream=None)
    logging.debug('global sudo enabled for all hosts')

global_user = args.user
logging.debug(f'global user set as {global_user}')

# Initial Global variables
class SSH_remote_host():
    def __init__(self, host, username, custom_sudopw=False):
        self.host = str(host)
        self.username = username
        if custom_sudopw:
            self.sudopass = getpass.getpass(prompt=f'sudo password for {self.host}',
                stream=None) 
        else:
            self.sudopass = global_sudo
        self.port = 22
        self.connection = paramiko.SSHClient()
        self.connection.load_system_host_keys()
        self.connection.set_missing_host_key_policy(paramiko.client.WarningPolicy())
        logging.debug(f'ssh class created for {self.username}@{self.host}:{self.port} customsudo password = {custom_sudopw}')

    def connect(self):
        self.connection.connect(self.host, self.port, self.username)
        logging.info(f'connected to {self.host}')
        logging.debug(f'connected to {self.username}@{self.host}:{self.port}') 

    def run_command(self, command, sudo=False):
        if sudo:
            # TODO issues with running sudo commands and passing input
            channel = self.connection.invoke_shell()
            channel.send(command)
            time.sleep(1)
            if channel.recv_ready():

            channel.send(f"{self.sudopass}\n")
            data = stdout.read.splitlines()
            remote_result = data
            logging.debug(f'{command} on {self.host} returned: {remote_result}')
            logging.info(f'command run on {self.host}')

            # any return cleanup?
        else:
            logging.debug(f'attempting to run {command} on {self.host} sudo=False')
            stdin, stdout, stderr = self.connection.exec_command(command)
            return_output = stdout.readlines()
            logging.info(f'command run on {self.host}')
            # any return cleanup?
            # TODO cleanup returns
            remote_result = return_output
        self.close()
        logging.info(f'connection closed with {self.host}')
        return remote_result

    def close(self):
        self.connection.close()
        logging.info(f'closed connection to {self.host}')

def convert_to_json(fname,data):
    logging.info(f'writing data to file: {fname}')
    with open(f"ssh-key-inventory-{fname}.json", "w") as outfile:
        json.dump(data, outfile)
    return

def generate_hosts():
    ''' Generate a list of ip address objects based on global arguments or
    global argument provided textfile. Resolve fqdn to ip address'''
    logging.info('generating hosts')
    ip_hosts = []
    if args.targetfile.is_file():
        hosts = args.targetfile.read_text().strip().split('\n')
        logging.debug('using Targetfile')
    else:
        logging.error('targetfile not found, please create it in the cwd')
    for ehost in hosts:
        try:
            ip = ipaddress.ip_address(getipaddress(ehost))
            logging.info(f'generated {ip} for {ehost}')

        except ValueError:
            logging.error(f'an element in the provided target string: {ehost} could not parsed, please check the inputs')
            raise ParsingError('the text provided for targets could not be parsed')
        ip_hosts.append(ip)
        # check for other error types
    logging.debug(f'generated {len(ip_hosts)} ip_hosts')
    return ip_hosts

def get_users(ssh_client):
    logging.debug(f'enumerating users for {ssh_client.host}')
    command = "cat /etc/passwd | grep -ve 'nologin$' -ve 'false$' -ve 'sync$'"
    remote_users = ssh_client.run_command(command)
    if remote_users:
        logging.info(f'found {len(remote_users)} on host {ssh_client.host}')
        return remote_users
    else:
        logging.error(f'no users found for {ssh_client.host}')
        raise Exception(f'no users found for {ssh_client.host} there is an error with this host or the /etc/password file... or this script!')
    # return a list of users

def get_pubkeys(remote_user):
    ''' Gets the public keys for the given remote user, this assumes the default
    location for all of the authorized keys files
    '''
    logging.debug(f'enumerating keys for {remote_user} on {ssh_client.host}')
    if remote_user == 'root':
        command = "cat /root/.ssh/authorized_keys"
    else:
        command = f"cat /home/{remote_user}/.ssh/authorized_keys"
    key_list = ssh_client.run_command(command, sudo=True)
    logging.info(f'found {len(key_list)} keys for user {remote_user} on {ssh_client.host}')
    return remoteuser_pubkeys

def run_commandset(host):
    ''' Get the a record of keys:users per host. Host is an object based on the
    SSH_remote_host class. records returned as a list of
    dictionaries'''
    host_records = []
    userlist = get_users(host)
    command_time = datetime.datetime.now(datetime.timezone.utc)
    for e_user in userlist:
        pubkeys = get_pubkeys(e_user)
        for e_pubkey in pubkeys:
            record = {'key' : e_pubkey, 'user' : e_user, 'host' : host.host,
                    'time' : command_time}
            host_records.append(record)
    return host_records

def main():
    allrecords = []
    hosts = generate_hosts()
    # TODO - add capability to run in parallel 
    for host in hosts:
        try:
            pdb.set_trace()
            client = SSH_remote_host(host, global_user)
            hostrecords = run_commandset(client)
            allrecords = allrecords + hostrecords
            logging.info(f'new {host} records written to allrecords')
        except:
            logging.error(f'an error occured running the commands on host:{host}')
        finally:
            client.close()
        convert_to_json(datetime.datetime.today(),allrecords)
    return

if __name__ == '__main__':
    main()
