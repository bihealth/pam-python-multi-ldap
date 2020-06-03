"""PAM module for multiple upstream LDAP servers based on
``pam_python.so``.

Tested with Python 2 on CentOS 7.7 but should work with Python 3 as
well.
"""

__author__ = "Franz Marko, Manuel Holtgrewe"

try:
    import ConfigParser as configparser  # py2
except ImportError:
    import configparser  # py3

import re
import sys

import ldap


#: Path to the global configuration file.
PATH_CONFIG = "/etc/pam_multi_ldap.ini"

#: LDAP connection timeout in seconds.
CONNECTION_TIMEOUT = 5


class DomainConfig:
    """Represent configuration for a single LDAP domain/upstream server."""

    def __init__(
        self,
        name,
        suffix,
        ldap_uris,
        ldap_user_name,
        ldap_search_base,
        ldap_bind_dn,
        ldap_bind_pw,
        ldap_search_filter=None,
    ):
        #: Domain name.
        self.name = name
        #: User name suffix for differentiating users.
        self.suffix = suffix
        #: List of LDAP URI(s) to try.
        self.ldap_uris = ldap_uris
        #: The user name attribute in the LDAP server.
        self.ldap_user_name = ldap_user_name
        #: LDAP search base to use.
        self.ldap_search_base = ldap_search_base
        #: Distinguished name for initially binding to LDAP server.
        self.ldap_bind_dn = ldap_bind_dn
        #: Password for initially binding to LDAP server.
        self.ldap_bind_pw = ldap_bind_pw
        #: Optional LDAP search filter expression.
        self.ldap_search_filter = ldap_search_filter


def load_configs(path):
    """Load configuration from the given path.

    Returns the configuration as a list of ``DomainConfig`` objects.
    """
    # Load configuration.
    config = configparser.RawConfigParser({"ldap_search_filter": None})
    config.read(path)
    # Convert to list of DomainConfig objects.
    result = []
    for name in config.sections():
        result.append(
            DomainConfig(
                name=name,
                suffix=config.get(name, "suffix"),
                ldap_uris=config.get(name, "ldap_uri").split(","),
                ldap_user_name=config.get(name, "ldap_user_name"),
                ldap_search_base=config.get(name, "ldap_search_base"),
                ldap_bind_dn=config.get(name, "ldap_bind_dn"),
                ldap_bind_pw=config.get(name, "ldap_bind_pw"),
                ldap_search_filter=config.get(name, "ldap_search_filter"),
            )
        )
    return result


def _get_user_dn(config, user_name):
    """Obtain distinguished name of the user with the given user name in the
    LDAP server with the given configuration.
    """
    # Build the LDAP query and incorporate search filter if any.
    ldap_query = "(%s=%s)" % (config.ldap_user_name, user_name)
    if config.ldap_search_filter:
        expr = config.ldap_search_filter
        if not expr.startswith("("):
            expr = "(%s)" % config.ldap_search_filter
        ldap_query = "(&%s%s)" % (ldap_query, expr)

    # Connect to LDAP servers (fallback in case of timeout)
    for ldap_uri in config.ldap_uris:
        try:
            con = ldap.initialize(ldap_uri)
            con.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            con.set_option(ldap.OPT_TIMEOUT, CONNECTION_TIMEOUT)
            con.simple_bind_s(config.ldap_bind_dn, config.ldap_bind_pw)
            result = con.search_s(
                config.ldap_search_base, ldap.SCOPE_SUBTREE, ldap_query, [""]
            )
            return result[0][0]
        except ldap.SERVER_DOWN:
            pass  # try next
    return None  # failed; will return above on success


def _bind_as_user(config, user_dn, user_pw):
    """Attempt to bind to the LDAP server with the given configuration using
    the given user DN and password.
    """
    for ldap_uri in config.ldap_uris:
        try:
            con = ldap.initialize(ldap_uri)
            con.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            con.set_option(ldap.OPT_TIMEOUT, CONNECTION_TIMEOUT)
            res = con.simple_bind_s(user_dn, user_pw)
            return res[0] == 97
        except ldap.SERVER_DOWN:
            pass  # try next
    return False  # failed; will return above on success


def pam_sm_authenticate(pamh, flags, argv):
    """Implement the ``pam_authenticate(3)`` interface."""
    # Load configuration.
    configs = load_configs(PATH_CONFIG)

    # Query the user for their password.
    pamh.authtok = pamh.conversation(
        pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Password:")
    ).resp

    # Find the first matching configuration.
    for config in configs:
        if pamh.user.endswith(config.suffix):
            break  # config is in config now
    else:  # no break above
        return pamh.PAM_AUTH_ERR

    # First step: bind as "bind user" and get DN of user to log in.
    user_dn = _get_user_dn(config, pamh.user[: -len(config.suffix)])
    if not user_dn:
        return pamh.PAM_AUTH_ERR

    # Second step: bind as user.
    if _bind_as_user(config, user_dn, pamh.authtok):
        return pamh.PAM_SUCCESS
    else:
        return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    """This service does not implement the ``pam_setcred(3)`` interface."""
    return pamh.PAM_CRED_UNAVAIL
