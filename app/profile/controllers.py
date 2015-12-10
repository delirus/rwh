from os import path, mkdir
from subprocess import call
from flask import Blueprint, request, session, make_response, render_template, flash, redirect, url_for, jsonify

from app import db, rwh
from app.auth.controllers import authenticated, authorized, get_login_session


"""
The blueprint for hadling URL's under the /profile/* path.
These paths are to be used for active user settings.
"""
profile_blueprint = Blueprint('profile', __name__, url_prefix='/profile')


def recreate_key(profile_directory, key_name):
    """
    Removes the private key with the name "key_name" in the "profile_directory"
    and its corresponding public key "key_name.pub" if they exist
    and calls ssh-keygen to create new key pair in the same directory
    with the same names.
    """
    if (not path.isdir(profile_directory)):
        mkdir(profile_directory)

    key_file = path.join(profile_directory, key_name)
    
    if path.isfile(key_file):
        remove(key_file)
    if path.isfile("%s.pub" % key_file):
        remove("%s.pub" % key_file)
    
    call("ssh-keygen -t rsa -b 2048 -C 'RedditWriterHelper' -f %s -P ''" % key_file, shell=True)


@profile_blueprint.route('/sshkey')
@authorized
def sshkey():
    """
    Local API endpoint that returns the public key for the current user.
    If the current user does not have a public/private key pair,
    one is created for him and the public key is returned in the response body.
    """
    key_name = 'id_rsa'

    login_session, session_id = get_login_session()

    profile_directory = path.join((rwh.config['RWH_DATA']), login_session.username)
    public_key_filename = path.join(profile_directory, "%s.pub" % key_name)

    if (request.method == 'GET'):
        if path.isdir(profile_directory):
            if (not path.isfile(public_key_filename)):
                recreate_key(profile_directory, key_name)
        else:
            recreate_key(profile_directory, key_name)

    public_key_file = open(public_key_filename, 'r')
    public_key = public_key_file.read().replace('\n', '')
    public_key_file.close()

    return public_key


@profile_blueprint.route('/settings', strict_slashes=False)
@authenticated
def settings():
    """
    what's up, doc?
    """
    return render_template('profile/settings.html')
