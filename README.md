## Simple Authn(cache)/Authz Lua module for Nginx

### What's authn & authz?

For those who already has the knowledge, just skip this part.

A typical permission system has two stage of auth, `authentication` which identifies a valid user
(has account in the system), and `authorization` which identifies if the user has permission
to access the given app.

### What are and why these two module?

#### simpleauthn_cookie.lua

This is not a real authn module, but just a cache powered by Cookie. Sometimes it is too
heavy to request authn module for each request, say, you are using an LDAP authn module, you
may wish to cache the authn result in Cookie, and check directly in nginx to avoid heavy traffic
to LDAP server.

#### simpleauthz.lua

Authz module can be as easy as "only allow alice and bob to access all content", and as compicated
as "only allow those who have Obama's phone number can send gift to RMS". However, for many cases
we only need a very simple user list/group based authz. like:

    app1: allow alice, bob, @hr-group
    app2: allow tom, jerry
    app3: allow all staff

We do not want to setup a database and handy php codes to serve just such a simple task, so comes
this module.

### Example Usage

#### Case 1
Use ldap as authn backend, allow all valid ldap user to access all contents, cache authn results in cookie.

    lua_package_path '/path/to/module/?.lua;;';
    init_by_lua 'simpleauthn = require "simpleauthn_cookie"
                 simpleauthn.set_secret_key("your-secret")  -- type some random bits
                 simpleauthn.set_max_age(3600)              -- the auth will be valid for one hour
                 simpleauthn.set_auth_url_fmt('/auth/?%s')  -- %s will be substitute with next=$current_url
                ';

    ldap_server ldapserver {
        url ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=person);
        binddn "cn=someuser,ou=people,dc=example,dc=com";
        binddn_password "somepassword";
        group_attribute cn;
        group_attribute_is_dn on;
        require valid_user;
    }

    server {
        server_name apps.example.com;

        location / {
            # simpleauthn.access() will first try analyse cookie to see if the user is logged in,
            # if the user is logged in, access will be granted, otherwise, he will be redirected
            # to /auth/?next=$current_url.
            access_by_lua 'simpleauthn.access()';
        }

        location /auth/ {
            # This is the real authn module, which use LDAP as authn backend.
            auth_ldap "LDAP Login";
            auth_ldap_servers ldapserver; 

            # If the previous LDAP auth is success, the user name will be stored in ngx.var.remote_user
            # simpleauthn.set_cookie() will generate auth info and send to user browser
            default_type 'text/html';
            content_by_lua 'simpleauthn.set_cookie(ngx.var.remote_user, "apps.example.com")';
        }
    }

#### Case 2
Use ldap authn backend, require simple uid/group based access control

    lua_package_path '/path/to/module/?.lua;;';
    init_by_lua '-- init authz
                 simpleauthz = require "simpleauthz"
                 simpleauthz.create_group("group1", "alice", "bob", ...)
                 simpleauthz.create_group("group2", "tom", "jerry", "@group1", ...)

                 simpleauthz.create_rule("RULE1", "allow", {"@group1", "Obama"}, {})
                 simpleauthz.create_rule("RULE2", "allow", {"@group2", "alice"}, {"jerry"})
                 simpleauthz.create_rule("RULE3", "deny", {"@group1"}, {})

                 -- init authn
                 simpleauthn = require "simpleauthn_cookie"
                 simpleauthn.set_secret_key("your-secret")
                 simpleauthn.set_max_age(3600)
                 simpleauthn.set_auth_url_fmt("/auth/?%s")
                ';

    server {
        server_name apps.example.com;

        location /auth/ { ...  }

        location /app1/ {
            ## This is very dangerous! It does not do any authn, just trust the query string uid=xxx.
            ## for RULE1: alice, bob, Obama will have access to app1
            access_by_lua 'simpleauthz.access("RULE1", ngx.var.arg_uid)';
        }

        location /app2/ {
            ## This is not that user friendly. If a user is logged in, the uid will be tested against RULE2,
            ## otherwise, 403 is returned instead of redirect to an auth url.
            ## for RULE2: tom, alice will be allowed, jerry and all others will be denied.
            access_by_lua 'simpleauthz.access("RULE2", simpleauthn.get_uid())';
        }

        location /app3/ {
            ## Note the params, the second param is a function, while the third is result of a function call.
            ## The authz module will first invoke simpleauthn.get_uid() to get the current uid, if uid is nil which
            ## means user is not logged in, he will be redirected to auth_url.
            ## for RULE3: alice and bob will be denied while all other logged in users will be allowed.
            access_by_lua 'simpleauthz.access_with_authn("RULE3", simpleauthn.get_uid, simpleauthn.get_auth_url())';
        }

        ## there are two predefined rules, ALLOW_ALL and DENY_ALL, just as the name indicates, all logged in users
        ## will be allowed/denied.
        location /app4/ { access_by_lua 'simpleauthz.access("ALLOW_ALL", ngx.var.arg_uid)'; }
        location /app5/ { access_by_lua 'simpleauthz.access("DENY_ALL", ngx.var.arg_uid)'; }

        location /app6/ {
            ## The authz module can also be used along with nginx basic auth modules.
            ## in this case, all logged in users and clients from 192.168.0.0/24 (may not be logged in) will have access
            ## to app6.
            satisfy any;
            allow 192.168.0.0/24;
            deny all;
            access_by_lua 'simpleauthn.access()';
        }
    }

## TODO

* Create a lua ldap authn module. The [nginx-ldap-module](https://github.com/kvspb/nginx-auth-ldap) is not shipped with nginx
  official release tarbal, we have to compile nginx by hand. If there is a pure lua ldap authn module, no compilation is needed.

