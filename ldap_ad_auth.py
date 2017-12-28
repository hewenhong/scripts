#!/usr/bin/env python
# encoding: utf-8
'''
@author: vincent

'''

import ldap
import argparse

def get_args():
    """ Get arguments from CLI """
    parser = argparse.ArgumentParser(
        description='Arguments for talking to LDAP')

    parser.add_argument('-l', '--host',
                        required=True,
                        action='store',
                        help='ldap/ad service to connect to')

    parser.add_argument('-o', '--port',
                        type=int,
                        default=389,
                        action='store',
                        help='Port to connect on')

    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='Username to use')

    parser.add_argument('-p', '--password',
                        required=False,
                        action='store',
                        help='Password to use')

    parser.add_argument('-b', '--base_dn',
                        required=True,
                        action='store',
                        help='base dn to ldap/ad')
    parser.add_argument('-t', '--server_type',
                        required=True,
                        action='store',
                        help='server type ldap/ad')

    args = parser.parse_args()
    return args


class BaseLoginServerAuth(object):
    '''  base login server authentication '''

    def __init__(self, server_host, base_dn, server_port=ldap.PORT):
        self.uri = "ldap://%s:%s" % (server_host, server_port)
        self.basedn = base_dn
        self.conn = None

    def _conn(self):
        if self.conn:
            return self.conn
        conn = ldap.initialize(self.uri)
        conn.protocol_version = 3
        conn.set_option(ldap.OPT_REFERRALS, 0)
        self.conn = conn
        return self.conn


class ADLoginServerAuth(BaseLoginServerAuth):
    ''' windows AD server authentication '''

    def __init__(self, server_host, base_dn, server_port=ldap.PORT):
        super(ADLoginServerAuth, self).__init__(server_host, base_dn, server_port)

    def login(self, auth_user, auth_passwd):
        try:
            # login
            conn = self._conn()
            conn.simple_bind_s(auth_user, auth_passwd)

            # get user info
            ret = conn.search_s(
                self.basedn, ldap.SCOPE_SUBTREE,
                "(userPrincipalName=%s)" % auth_user,
                ["displayName", "userPrincipalName", "objectGUID"])
            if ret is None or len(ret) == 0:
                print "login to ad server [%s] succeeded but [%s] not found" % (self.uri, auth_user)
                return None
            user_info = ret[0][1]
        except Exception, e:
            print "login to ad server [%s] for [%s] failed, [%s]" % (self.uri, auth_user, e)
            return None
        finally:
            conn.unbind_s()
        return user_info


class LDAPLoginServerAuth(BaseLoginServerAuth):
    '''linux ldap server authentication'''
    def __init__(self, server_host, base_dn, server_port=ldap.PORT):
        super(LDAPLoginServerAuth, self).__init__(server_host, base_dn, server_port)

    def login(self, auth_user, auth_passwd):
        try:
            # login
            user_name = auth_user.split('@')[0]
            conn = self._conn()
            user_dn = "cn=%s," % user_name + self.basedn
            conn.simple_bind_s(user_dn, auth_passwd)
            # get user info
            ret = conn.search_s(
                self.basedn, ldap.SCOPE_SUBTREE,
                "cn=%s" % user_name)
            if ret is None or len(ret) == 0:
                return None
            user_info = ret[0][1]
        except Exception, e:
            print "login to ldap server [%s] for [%s] failed, [%s]" % (self.uri, auth_user, e)
            return None
        finally:
            conn.unbind_s()
        return user_info

def main():
    args = get_args()
    if args.server_type == 'ad':
        login_server = ADLoginServerAuth(args.host, args.base_dn, args.port)
    elif args.server_type == 'ldap':
        login_server = LDAPLoginServerAuth(args.host, args.base_dn, args.port)
    else:
        print "not support type"
    user = login_server.login(args.user, args.password)
    print user

if __name__ == '__main__':
    main()

