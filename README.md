# openssh-vault-refresher
SSH Authentication using CA certificates is a very rare, but powerfull soution. This project contains simple script to refresh your ssh certificate from a [Vault SSH](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html) certificate storage - _only when needed/expired_. In this way you can grant access to your infrastructure only for short period of time (like 1 day) and easy retrieve new certificate when this time expired. As long as user is authorize to access Vault they can prolong an access (Vault provide many methods of authentication and authorization - static/LDAP,other ...) - no changes on a servers, just certificate from Vault for user.

 You can set-up it in your `.bash_login` script and certificates will be refreshed when they are almost expired. I wrote it to check expiration parameters of SSH certificates as described in [OpenSSH documentation](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys) to avoid unnecessary network traffic and Vault access requirement

### Overview
When using Immutable Infrastructure concept you should avoid changes (or they are even not possible without re-deploy). Using Vault you can grant access to 'infrastructure' role in your organization and users can generate certificates that allows them to log-in to all your systems within provided timeframe and limits (username, hosts, command). On a machine there will be still the same CA certificate without any changes. All you have to do is to obtain a valid certificate from a CA (in this case maintained by Vault). Since 2010 OpenSSH project contains a support for CA certificates but from my observation they are rarely used.

This concept isn't new, Netflix created [Blees](https://github.com/Netflix/bless) solution for that - it's more complicated but also more powerful. In this example we are using [Vault](https://www.vaultproject.io) that contains support for ssh keys and can be simple configured to fit our needs.

### Setup
You have to set-up Vault repository as described in a [documentation](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html). Later we assume that you have an *token* that can access a *user role* to generate a certificate.

### Test setup

Simple setup to evaluate this solution:

#### Set-up dev vault server
* Start a Vault dev server via command: `vault server -dev`
* From a generated output please set-up a *VAULT_ADDR* environment variable accordingly and copy *root token*
* Please authorize to your vault: `vault auth` and provide a root token
* Mount ssh backend: `vault mount ssh`
* Generate new CA: `vault write ssh/config/ca generate_signing_key=true`
* Add new role that allows signature creation:
```
vault write ssh/roles/infra -<<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "ttl": "30m0s"
}
EOH
```

#### Add SSH CA to the sshd
* On a destination server you have to enable CA. Please download public CA certificate: `curl -o /etc/ssh/trusted-user-ca.pub $VAULT_ADDR/v1/ssh/public_key`
* Add line into */etc/sshd_config*
```
# /etc/ssh/sshd_config
# ...
TrustedUserCAKeys /etc/ssh/trusted-user-ca.pub
```
* Restart sshd server, now server allows users with valid certificate to log-in to the system

#### Sign new keys
* Generate new key, not added to any server: `ssh-keygen -f test_key`
* Create a certificate by launching a script from this repository: `python check-cert-and-update.py -t <token> -s ssh/sign/infra -v $VAULT_ADDR -k test_key` - First run should detect that there is no cert and download it from a vault repository. *This script uses `requests` and `paramiko` modules, you can install them by typing: `pip install requests paramiko`*
* Log-in to an existing account on a server with enabled CA: `ssh -i test_key root@my-machine`
