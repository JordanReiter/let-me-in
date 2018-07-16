#!/usr/bin/env python
from __future__ import print_function

import logging
from logging.handlers import RotatingFileHandler

import json
import datetime
import re

import flask
from flask import Flask, Response, abort, request, render_template, redirect, flash

import os

from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

from .auth import Auth

auth = Auth(app)


import collections

SECURITY_GROUP = os.environ.get('SECURITY_GROUP', '')
CANCEL_URL = os.environ.get('CANCEL_URL', '/')
APP_NAME = os.environ.get('APP_NAME') or 'AWS Log In'
RETURN_VAR = os.environ.get('RETURN_VAR') or 'return'

ACCESS_GROUPS = os.environ.get('GROUPS_WITH_ACCESS', '').split(",")
ADMIN_GROUPS = os.environ.get('GROUPS_WITH_ADMIN', '').split(",")

from .utils import add_ip, clear_ips, remove_ip, ip_is_in_group

SecurityGroupRule = collections.namedtuple("SecurityGroupRule", ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])

@app.context_processor
def global_variables():
    return dict(
        logout_url=auth.logout_url,
        app_name=APP_NAME,
        PREFIX=flask.request.script_root,
        return_var=RETURN_VAR,
        user=auth.user,
    )

@app.route('/knock/', methods=['GET', 'POST'])
@auth.login_required
def knock():
    if not auth.has_access(check_groups=ACCESS_GROUPS + ADMIN_GROUPS):
        return Response( "Not allowed.", status=403, mimetype="text/plain")
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if request.method != 'POST':
        return render_template('knock.html', user=auth.user, cancel_url=CANCEL_URL,  ip=ip_address)
    add_ip(SECURITY_GROUP, ip_address)
    return redirect(flask.request.script_root + '/knocked/')

@app.route('/knocked/', methods=['GET'])
@auth.login_required
def knocked():
    if not auth.has_access(check_groups=ACCESS_GROUPS + ADMIN_GROUPS):
        return Response( "Not allowed.", status=403, mimetype="text/plain")
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if not ip_is_in_group(SECURITY_GROUP, ip_address):
        flash('Your IP address was not added. Please try again.', 'warning')
        return redirect(flask.request.script_root + '/knock/')
    return render_template('knocked.html', user=auth.user, ip=ip_address)

@app.route('/', methods=['GET'])
@auth.login_required
def hello():
    if not auth.has_access(check_groups=ACCESS_GROUPS + ADMIN_GROUPS):
        return Response( "Not allowed.", status=403, mimetype="text/plain")
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    return render_template('hello.html', ip=ip_address)

@app.route('/goodbye/', methods=['GET', 'POST'])
@app.route('/bye/', methods=['GET', 'POST'])
@auth.login_required
def goodbye():
    if not auth.has_access(check_groups=ACCESS_GROUPS + ADMIN_GROUPS):
        return Response( "Not allowed.", status=403, mimetype="text/plain")
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if request.method != 'POST':
        return render_template('goodbye.html', user=auth.user, cancel_url=CANCEL_URL, ip=ip_address)
    remove_ip(SECURITY_GROUP, ip_address)
    return redirect(flask.request.script_root + '/left/')

@app.route('/left/', methods=['GET'])
@auth.login_required
def left():
    if not auth.has_access(check_groups=ACCESS_GROUPS + ADMIN_GROUPS):
        return Response( "Not allowed.", status=403, mimetype="text/plain")
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if ip_is_in_group(SECURITY_GROUP, ip_address):
        flash('Your IP address was not removed. Please try again.', 'warning')
        return redirect(flask.request.script_root + '/goodbye/')
    return render_template('left.html', user=auth.user, ip=ip_address)

@app.route('/clear/', methods=['GET', 'POST'])
@auth.login_required
def clearall():
    if not auth.has_access(check_groups=ADMIN_GROUPS):
        return Response( "Not allowed.", status=403, mimetype="text/plain")
    if request.method != 'POST':
        return render_template('clear-confirm.html', user=auth.user, cancel_url=CANCEL_URL)
    ip_count = len(clear_ips(SECURITY_GROUP))
    return redirect(flask.request.script_root + '/cleared/?count={}'.format(ip_count))

@app.route('/cleared/', methods=['GET'])
@auth.login_required
def cleared():
    if not auth.has_access(check_groups=ACCESS_GROUPS + ADMIN_GROUPS):
        return Response( "Not allowed.", status=403, mimetype="text/plain")
    ip_count=request.args.get('count')
    if not ip_count:
        flash('No IP addresses were cleared. Please try again.', 'warning')
        return redirect(flask.request.script_root + '/clear/')
    return render_template('cleared.html', user=auth.user, cleared=ip_count)


class ReverseProxied(object):
     '''Wrap the application in this middleware and configure the 
front-end server
     to add these headers, to let you quietly bind this to a URL other 
than /
     and to an HTTP scheme that is different than what is used locally.

     In nginx:
         location /myprefix {
             proxy_pass http://192.168.0.1:5001;     # where Flask app runs
             proxy_set_header Host $host;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
             proxy_set_header X-Scheme $scheme;
             proxy_set_header X-Script-Name /myprefix;
             }

     :param app: the WSGI application
     '''
     def __init__(self, app):
         self.app = app

     def __call__(self, environ, start_response):
         script_name = environ.get('HTTP_X_SCRIPT_NAME', '')
         if script_name:
             environ['SCRIPT_NAME'] = script_name
             path_info = environ['PATH_INFO']
             if path_info.startswith(script_name):
                 environ['PATH_INFO'] = path_info[len(script_name):]

         scheme = environ.get('HTTP_X_SCHEME', '')
         if scheme:
             environ['wsgi.url_scheme'] = scheme
         return self.app(environ, start_response)

app.wsgi_app = ReverseProxied(app.wsgi_app)


if __name__ == '__main__': # pragma: no cover
    handler = RotatingFileHandler('mylog.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.run()
