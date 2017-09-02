#!/usr/bin/python
import requests
import base64
import sys
import os
import logging

from argparse import ArgumentParser
from sys import exit
from  datetime import datetime
from paramiko.message import Message

#Based on RFC4252 & https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys

PUB_KEY_SUFFIX = ".pub"
CERT_KEY_SUFFIX = "-cert.pub"

class CertUpdater:

    def __init__(self, key_path):
        self.key_path = key_path

    def priv_and_pub_key_exists(self):
        return os.path.exists(self.key_path) and os.path.exists(self.key_path + PUB_KEY_SUFFIX)

    def is_cert_valid(self):
        cert_path = self.key_path + CERT_KEY_SUFFIX

        if not os.path.exists(cert_path):
            logging.debug("Certficate doesnt exists - %s", cert_path)
            return False

        content = open(cert_path, "r").read().split(' ')
        if len(content) < 2:
            logging.debug("Certificate [%s] in a wrong format - %s", cert_path, content)
            return False

        payload = base64.b64decode(content[1])
        msg = Message(payload)
        msg_type = msg.get_string().decode("ascii")

        if msg_type != content[0]:
            logging.warn("Wrong SSH cert header at file %s: %s vs %s", cert_path, content[0], msg_type)
            return False

        if msg_type == "ssh-rsa-cert-v01@openssh.com":
            (valid_after, valid_before) = self._read_rsa_dates(msg)
            return self._check_dates(valid_after, valid_before)
        elif msg_type == "ssh-dss-cert-v01@openssh.com":
            (valid_after, valid_before) = self._read_dsa_dates(msg)
            return self._check_dates(valid_after, valid_before)
        elif msg_type in ["ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com"]:
            (valid_after, valid_before) = self._read_ecdsa_dates(msg)
            return self._check_dates(valid_after, valid_before)
        elif msg_type == "ssh-ed25519-cert-v01@openssh.com":
            (valid_after, valid_before) = self._read_ed25519_dates(msg)
            return self._check_dates(valid_after, valid_before)
        else:
            logging.error("Certificate format not supported: %s - %s", cert_path, msg_type)
            return False

    def _check_dates(self, valid_after, valid_before):
        now = datetime.now()
        if  now < datetime.fromtimestamp(valid_after):
            return False
        elif now > datetime.fromtimestamp(valid_before):
            return False
        else:
            return True

    def _read_rsa_dates(self, msg):
        nonce = msg.get_string()
        e = msg.get_mpint()
        n = msg.get_mpint()
        serial = msg.get_int64()
        key_type = msg.get_int()
        key_id = msg.get_string()
        principals = msg.get_string()
        valid_after = msg.get_int64()
        valid_before = msg.get_int64()

        return (valid_after, valid_before)

    def _read_dsa_dates(self, msg):
        nonce = msg.get_string()
        p = msg.get_mpint()
        q = msg.get_mpint()
        g = msg.get_mpint()
        y = msg.get_mpint()
        serial = msg.get_int64()
        key_type = msg.get_int()
        key_id = msg.get_string()
        principals = msg.get_string()
        valid_after = msg.get_int64()
        valid_before = msg.get_int64()

        return (valid_after, valid_before)

    def _read_ecdsa_dates(self, msg):
        nonce = msg.get_string()
        curve = msg.get_string()
        public_key = msg.get_string()
        serial = msg.get_int64()
        key_type = msg.get_int()
        key_id = msg.get_string()
        principals = msg.get_string()
        valid_after = msg.get_int64()
        valid_before = msg.get_int64()

        return (valid_after, valid_before)

    def _read_ed25519_dates(self, msg):
        nonce = msg.get_string()
        pk = msg.get_string()
        serial = msg.get_int64()
        key_type = msg.get_int()
        key_id = msg.get_string()
        principals = msg.get_string()
        valid_after = msg.get_int64()
        valid_before = msg.get_int64()

        return (valid_after, valid_before)

    def update_cert_from_vault(self, url, role, token, hostname = None):
        logging.info("Downloading new certificate from Vault: [%s] using role %s", url, role)
        public_key = open(self.key_path + PUB_KEY_SUFFIX, "r").read()
        payload = {'public_key': public_key}
        if hostname is not None:
            payload['valid_principals']=hostname
            payload['cert_type'] = 'host'
        else:
            payload['cert_type'] = "user"

        headers = {'X-Vault-Token': token}
        r = requests.post(url + "/v1/" + role, json=payload, headers=headers)
        if r.status_code == 200:
            new_cert = r.json()['data']['signed_key']
            open(self.key_path + CERT_KEY_SUFFIX, "w").write(new_cert)
            logging.info("New certificate obtained successfully.")
            exit(0)
        else:
            logging.error("Error during communication with Vault service %s: %s", url, r.text)
            exit(1)

if __name__ == "__main__":
    parser = ArgumentParser(description="Check SSH certificate validity and refresh when needed. https://github.com/jsuchenia/openssh-vault-refresher")
    parser.add_argument("-t", "--token", help = "Token for vault server", required = True)
    parser.add_argument("-s", "--sign_path", help = "SSH sign path with role (like: ssh/sign/infra)", required = True)
    parser.add_argument("-v", "--vault_addr", help = "Vault address", required = True)
    parser.add_argument("-k", "--key", help = "SSH key path", required = True)
    parser.add_argument("--loglevel", help = "Define logging level", default="info", choices = ["error", "info", "debug"])
    args = parser.parse_args()

    numeric_level = getattr(logging, args.loglevel.upper(), None)
    logging.basicConfig(level = numeric_level)
    logging.debug("Arguments parsed: %s", args)

    cu = CertUpdater(args.key)
    if not cu.priv_and_pub_key_exists():
        logging.error("Public/private pair doesn't exists - please check a path %s", args.key)
        exit(1)
    if cu.is_cert_valid():
        logging.info("Certificate is still valid, there is no need to refresh it")
        exit(0)
    cu.update_cert_from_vault(args.vault_addr, args.sign_path, args.token)
