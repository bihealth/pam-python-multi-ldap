# Multi-LDAP PAM Module

This is a `pam_python.so` based PAM module for authenticating with multiple upstream repositories.

## Background

The BIH HPC has two sources for user accounts, one each for the upstream organisations (non-overlapping UIDs are guaranteed).
We use a "materialized" meta OpenLDAP server that stores copies of the necessary attributes of the upstream LDAP servers.
This has the advantage that to the HPC systems, we only have one source of users with simple to manage Unix groups.
Further, we have no passwords in our LDAP tree.
While good (as we don't have to care about password management), users cannot easily login with their passwords.

This repository contains our solution to this.
The file `src/pam_multi_ldap.py` that is a `pam_python.so` based PAM module for authenticating users to the upstream servers.
A central configuration file configures the available upstream repositories and a suffix in the user login name determines which upstream servers to use.

## Installing

You will need the Python `ldap` module as well as `pam_python.so`.

For CentOS 7:

```bash
root@host:~$ yum install -y python-pam python-ldap
```

The module has been written to work for both Python 2.7 and 3.6+.

Put the module into `/usr/local/lib/pam-multi-ldap`

```bash
root@host:~$ B=https://raw.githubusercontent.com/bihealth/pam-python-multi-ldap/src
root@host:~$ mkdir -p /usr/local/lib/pam-python-multi-ldap
root@host:~$ curl $B/pam_multi_ldap.py \
    > /usr/local/lib/pam-python-multi-ldap/pam_multi_ldap.py
root@host:~$ curl $B/pam_multi_ldap.ini.example \
    > /etc/pam_multi_ldap.ini
root@host:~$ chown root:root /etc/pam_multi_ldap.ini
root@host:~$ chmod u=rw,go= /etc/pam_multi_ldap.ini
```

## Configuring

Edit the file `/etc/pam_multi_ldap.ini` to configure one or more upstream repositories.

## Using

Use the following line in the appropriate `/etc/pam.d` file where you would otherwise use the `sss` module, for example.

```
auth       sufficient   pam_python.so /usr/local/lib/pam-python-multi-ldap/pam_multi_ldap.py
```
