AWS, Let Me In
=======================
|build| |coverage| |contributors| |license|

**AWS, Let Me In** solves the problem of providing SSH access to EC2 instances without 
having to use either the CLI or the AWS Console website. This is especially useful if you have users who should have SSH access but who don't have any access to administrative functions in AWS.

Let Me In is inspired by the traditional technique of `port knocking <https://en.wikipedia.org/wiki/Port_knocking>`_ where users would open a port by visiting other closed ports in a particular sequence. In this setup, visiting a (ideally) password protected page and then clicking on the "Add Access for <ip>" button will add the user's current IP address to a specified security group. 

Getting Started
---------------

To use this app, install it in the target directory ::

    cd /path/to/dir
    git clone https://github.com/JordanReiter/let-me-in.git let-me-in
    cd let-me-in
    # set up a virtualenv -- strongly recommended!
    virtualenv-2.7 . # Python 3 is supported by the app, but mod_wsgi uses Python 2.7 by default
    source bin/activate
    pip install -r requirements.txt
    # if you are using flask_cas for authentication:
    pip install flask_cas

**AWS, Let me in** is a standard WSGI app, so you can use your preferred method of connecting to the app.

Here is a sample configuration using mod_wsgi on Apache httpd::

    <VirtualHost *>
        WSGIDaemonProcess let-me-in python-home=/var/www/python-environments/let-me-in
        WSGIScriptAlias /letmein /var/www/python-environments/let-me-in/letmein/letmein.wsgi
        <Directory /var/www/python-environments/let-me-in>
            WSGIProcessGroup let-me-in
            WSGIApplicationGroup %{GLOBAL}
            Order deny,allow
            Allow from all
        </Directory>
    </VirtualHost>


Settings
--------

The following settings should be provided either as environmental variables or as entries in a .env file located inside of the letmein directory:

  - ``AWS_SECRET_ACCESS_KEY``, ``AWS_ACCESS_KEY_ID`` - required if you have the app installed on a server without an active IAM role. Otherwise, it uses standard boto3, which should work without credentials if an IAM role is correctly configured for the server.
  - ``SECRET_KEY`` -- a random sequence of characters to be used as a secret key. I believe this is standard to Flask.
  - ``GROUPS_WITH_ACCESS`` -- if you are using group-based authentication, these are the groups that can add IPs to the security group
  - ```GROUPS_WITH_ADMIN`` -- these groups are able to affect other users -- specifically, they are able to clear *all* IPs saved to the Security group. Note that it only affects security groups for the targeted port and does not include IP ranges with more than one IP address.
  - ``SECURITY_GROUP`` -- the security group that is changed by the app. The AWS user associated with the app must have the correct permissions for modifying groups.
  - ``AUTH_BACKEND`` -- the authentication backend to use for access to the app. The only secure, active backend currently available is ``auth.backends.cas.CASAuth``.

Authentication Backends
------------------------------------
The ``backends`` folder includes a base class that can be extended. Any authentication backend you create must implement the following methods:

 - has_access -- true if the user should have access to the page, false if they shouldn't
 - login_required -- should return a decorator that redirects to a login page if the user needs to sign in, or just returns the request if the user should have access
 - logout_url -- returns the url the user should be sent to on logout_url

 You can look at both ``auth/backends/cas.py`` and ``auth/backends/noauth.py`` for code that implements these (and other) functions.

Credits
-------
Thanks to Paulo Poiati and his article on testing flashes <http://blog.paulopoiati.com/2013/02/22/testing-flash-messages-in-flask/>

Thanks to Peter Hansen for the ReverseProxied class <http://flask.pocoo.org/snippets/35/>.

--------

.. |coverage| image:: https://img.shields.io/coveralls/JordanReiter/let-me-in/master.svg?style=flat-square
    :target: https://coveralls.io/r/JordanReiter/let-me-in?branch=master
    :alt: Test coverage

.. |build| image:: https://travis-ci.org/JordanReiter/let-me-in.svg?branch=master
    :target: https://travis-ci.org/JordanReiter/let-me-in

.. |contributors| image:: https://img.shields.io/github/contributors/JordanReiter/let-me-in.svg?style=flat-square
    :target: https://github.com/JordanReiter/let-me-in/graphs/contributors

.. |license| image:: https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square
    :target: https://raw.githubusercontent.com/JordanReiter/let-me-in/master/LICENSE
    :alt: Package license

.. _`the repository`: https://github.com/JordanReiter/let-me-in
