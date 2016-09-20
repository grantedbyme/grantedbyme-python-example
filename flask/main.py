"""
GrantedByMe Integration Demo

Copyright (c) 2016 grantedby.me

.. moduleauthor:: GrantedByMe <info@grantedby.me>
"""
# -*- coding: utf-8 -*-

import sys
import os
import os.path
import configparser
import json

import redis
from flask import Flask, request, redirect, url_for, render_template, make_response, jsonify, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin

base_path = os.path.dirname(os.path.abspath(__file__))

# load configuration
config = configparser.ConfigParser()
config.read(base_path + '/main.conf')

# setup system and key paths
if config['app']['BRANCH'] == 'local':
    sys.path.append('./../..')
    data_dir = '../../data/'
else:
    data_dir = config['app']['SECRET_DIR']

from grantedbyme import GrantedByMe, GBMCrypto, ChallengeType
import logging
from logging.handlers import RotatingFileHandler
import os

# create flask application
app = Flask(__name__, static_folder='static')
app.config.from_object(config['flask'])
if config['app']['BRANCH'] == 'local':
    app.config.from_object(config['flask-local'])

# configure logging
base_dir = os.path.dirname(os.path.realpath(__file__))
log_file = os.path.join(base_dir, 'logs/app.log')
handler = RotatingFileHandler(log_file, maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# setup flask login extension
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.init_app(app)

# create GrantedByMe python client
gbm = GrantedByMe(private_key_file=data_dir + 'private_key.pem',
                  server_key_file=data_dir + 'server_key.pem')

# create redis cache
redis = redis.StrictRedis(host=config['redis']['host'],
                          port=config['redis']['port'],
                          db=config['redis']['db'],
                          decode_responses=True)

if not redis.exists('user_counter'):
    redis.set('user_counter', 0)


def _user_add(email, authenticator_secret, first_name, last_name):
    if redis.exists('user_id_by_email_' + email):
        _flash_log('User already exists: ' + email)
        return None
    redis.incr('user_counter')
    user_id = redis.get('user_counter')
    app.logger.info('create_user: %s with user id: %s', email, user_id)
    user_data = {'authenticator_secret': authenticator_secret,
                 'email': email,
                 'first_name': first_name,
                 'last_name': last_name,
                 'user_id': user_id}
    if authenticator_secret:
        redis.set('user_id_by_authenticator_secret_' + authenticator_secret, user_id)
        redis.set('authenticator_secret_by_hash_' + GrantedByMe.hash_authenticator_secret(authenticator_secret), authenticator_secret)
    if email:
        redis.set('user_id_by_email_' + email, user_id)
    redis.set('user_by_id_' + user_id, json.dumps(user_data))
    _flash_log('User created: ' + str(user_id) + ' (' + email + ')')
    return user_id


def _user_update(user_id, authenticator_secret):
    if redis.exists('user_by_id_' + user_id):
        user_data = json.loads(redis.get('user_by_id_' + user_id))
        user_data['authenticator_secret'] = authenticator_secret
        if authenticator_secret:
            redis.set('user_id_by_authenticator_secret_' + authenticator_secret, user_id)
            redis.set('authenticator_secret_by_hash_' + GrantedByMe.hash_authenticator_secret(authenticator_secret), authenticator_secret)
        _flash_log('User updated: ' + str(user_id))
        return redis.set('user_by_id_' + user_id, json.dumps(user_data))
    else:
        _flash_log('User not found: ' + authenticator_secret)
    return False


def _user_get(authenticator_secret):
    if redis.exists('user_id_by_authenticator_secret_' + authenticator_secret):
        user_id = redis.get('user_id_by_authenticator_secret_' + authenticator_secret)
        user_data = redis.get('user_by_id_' + user_id)
        return json.loads(user_data)
    return None


def _user_login(user_id):
    if user_id:
        new_user = SiteUser(int(user_id))
        result = login_user(new_user)
        if result:
            _flash_log('Logged in with user id: ' + str(user_id))


def _flash_log(message):
    app.logger.info(message)
    flash(message)


@login_manager.user_loader
def login_user_loader(user_id):
    """TBD"""
    # app.logger.info('login_user_loader')
    # session_token = session['session_token']
    new_user = SiteUser(user_id)
    return new_user


@login_manager.unauthorized_handler
def not_authorized():
    """TBD"""
    # app.logger.info('not_authorized')
    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
@login_required
def index():
    """TBD"""
    app.logger.debug('index')
    return make_response(render_template('index.html'))


@app.route('/login', methods=['GET'])
def login():
    """TBD"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    app.logger.debug('login')
    return make_response(render_template('login.html'))


@app.route('/logout', methods=['GET'])
def logout():
    """TBD"""
    _flash_log('Logged out')
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET'])
def register():
    """TBD"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    app.logger.debug('register')
    return make_response(render_template('register.html'))


@app.route('/account', methods=['GET'])
@login_required
def account():
    """TBD"""
    app.logger.debug('account')
    return make_response(render_template('account.html'))


@app.route('/flushdb', methods=['GET'])
def flushdb():
    """TBD"""
    _flash_log('Database cleared')
    redis.flushdb()
    return redirect(url_for('logout'))


@app.route('/ping', methods=['GET'])
def ping():
    """TBD"""
    app.logger.debug('ping')
    return make_response(jsonify({'success': True}))


@app.route('/create_user/<email>', methods=['GET'])
def create_user(email):
    """TBD"""
    user_id = _user_add(email, None, None, None)
    _user_login(user_id)
    return redirect(url_for('index'))


@app.route('/auto_login/<user_id>', methods=['GET'])
def auto_login(user_id):
    """TBD"""
    if redis.exists('user_by_id_' + user_id):
        _user_login(int(user_id))
    else:
        _flash_log('User not exists: ' + str(user_id))
    return redirect(url_for('index'))


@app.route('/ajax', methods=['POST'])
def ajax():
    """TBD"""
    if request.is_xhr:
        client_ip = None
        client_ua = None
        if request.remote_addr:
            client_ip = request.remote_addr
        if 'User-Agent' in request.headers:
            client_ua = request.headers['User-Agent']
        if request.form['operation'] == 'getSessionState':
            response_data = _get_session_state()
        elif request.form['operation'] == 'getSessionToken':
            response_data = gbm.get_challenge(challenge_type=ChallengeType.authenticate.value, client_ip=client_ip, client_ua=client_ua)
        elif request.form['operation'] == 'getAccountState':
            response_data = _get_account_state()
        elif request.form['operation'] == 'getAccountToken':
            response_data = gbm.get_challenge(challenge_type=ChallengeType.authorize.value, client_ip=client_ip, client_ua=client_ua)
        elif request.form['operation'] == 'getRegisterState':
            response_data = _get_register_state()
        elif request.form['operation'] == 'getRegisterToken':
            response_data = gbm.get_challenge(challenge_type=ChallengeType.profile.value, client_ip=client_ip, client_ua=client_ua)
        app.logger.info('request: %s and response: %s', request.form, response_data)
    if not response_data:
        response_data = {'success': False}
    return make_response(jsonify(response_data))


def _get_session_state():
    """TBD"""
    response_data = gbm.get_challenge_state(request.form['challenge'])
    if response_data['success'] and response_data['status'] == 3:
        if redis.exists('user_id_by_authenticator_secret_' + response_data['authenticator_secret']):
            user_id = redis.get('user_id_by_authenticator_secret_' + response_data['authenticator_secret'])
            _user_login(user_id)
        else:
            _flash_log('Authentication error')
        del response_data['authenticator_secret']
    return response_data


def _get_account_state():
    """TBD"""
    response_data = gbm.get_challenge_state(request.form['challenge'])
    if response_data['success'] and response_data['status'] == 3:
        authenticator_secret = GrantedByMe.generate_authenticator_secret()
        result = gbm.link_account(request.form['challenge'], authenticator_secret)
        if result['success']:
            user_id = current_user.get_id()
            _user_update(user_id, authenticator_secret)
        else:
            _flash_log('Error migrating your account to GrantedByMe')
    return response_data


def _get_register_state():
    """TBD"""
    response_data = gbm.get_challenge_state(request.form['challenge'])
    if response_data['success'] and response_data['status'] == 3:
        authenticator_secret = GrantedByMe.generate_authenticator_secret()
        result = gbm.link_account(request.form['challenge'], authenticator_secret)
        if result['success']:
            email = response_data['data']['email']
            first_name = response_data['data']['first_name']
            last_name = response_data['data']['last_name']
            user_id = _user_add(email, authenticator_secret, first_name, last_name)
            del response_data['data']
        else:
            _flash_log('Error creating user account')
    return response_data


@app.route('/callback', methods=['POST'])
def callback():
    """TBD"""
    plain_response = {'success': False}
    if 'signature' in request.form and 'payload' in request.form:
        cipher_request = {
            'signature': request.form['signature'],
            'payload': request.form['payload']
        }
        if 'message' in request.form:
            cipher_request['message'] = request.form['message']
        plain_request = GBMCrypto.decrypt_compound(cipher_request, gbm.server_key, gbm.private_key)
        app.logger.info('callback: %s', plain_request)
        if 'operation' in plain_request:
            if plain_request['operation'] == 'ping':
                plain_response = {'success': True}
            elif plain_request['operation'] == 'unlink_account':
                authenticator_secret = redis.get('authenticator_secret_by_hash_' + plain_request['token'])
                user_id = redis.get('user_id_by_authenticator_secret_' + authenticator_secret)
                if _user_update(user_id, None):
                    plain_response = {'success': True}
            elif plain_request['operation'] == 'rekey_account':
                if redis.exists('authenticator_secret_by_hash_' + plain_request['token']):
                    authenticator_secret = redis.get('authenticator_secret_by_hash_' + plain_request['token'])
                    plain_response = {'success': True, 'authenticator_secret': authenticator_secret}
            else:
                app.logger.info('callback operation not handled: %s', plain_request['operation'])
    cipher_response = GBMCrypto.encrypt_compound(plain_response, gbm.server_key, gbm.private_key)
    return make_response(jsonify(cipher_response))


# JINJA 2


@app.context_processor
def get_cdn_host_processor():
    """Template engine preprocessor"""

    def get_cdn_host():
        """TBD"""
        return config['app']['CDN_HOST']

    return dict(get_cdn_host=get_cdn_host)


# LOGIN

class SiteUser(UserMixin):
    def __init__(self, user_id):
        self.user_id = user_id
        self.user_authenticated = True
        self.user_active = True
        self.user_anonymous = False

    def is_authenticated(self):
        return self.user_authenticated

    def is_active(self):
        return self.user_active

    def is_anonymous(self):
        return self.user_anonymous

    def get_id(self):
        return self.user_id


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006)
