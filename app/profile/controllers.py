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


@profile_blueprint.route('/giturl', methods=['GET', 'POST'])
@authorized
def giturl():
    """
    This API endpoint serves for reading and writing current profile git repo.

    It accepts HTTP methods GET (reading) and POST (writing).
    The GET request will a string with SSH username, server hostname
    and path to the repository (as used by git for checkout command,
    e.g. 'git@github.com:delirus/rwh.git')

    The POST method accepts 'text/html' content type (in UTF-8 charset)
    in the same format ('user@host:repo').

    The call will return error 401 if the request is not authenticated
    error 403 if it is not authorized, error 405 if the method is not allowed,
    error 415 if the POST request has bad content type
    (it must be 'text/html[; charset=utf-8'])
    and error 400 if the POSTed string is not in the required format.

    Successfull POST request will write the request data to a file 'repo.url'
    in the profile directory (<app_data_dir>/<sha256(username)>)
    and return the POST data back to client.
    
    Successfull GET request will return content of this file or empty string
    if the file does not exist.
    """
    url_file = 'repo.url' # name of the file with the git repo URL
    
    login_session, session_id = get_login_session()
    profile_directory = path.join((rwh.config['RWH_DATA']), login_session.username)
    # whole path to the file with the repo URL
    repo_url_filename = path.join(profile_directory, url_file)

    if (request.method == 'GET'):
        repo_url = ""

        if path.isfile(repo_url_filename):
            repo_url_file = open(repo_url_filename)
            repo_url = repo_url_file.read(post_data).replace('\n', '')
            repo_url_file.close()

        return repo_url

    elif (request.method == 'POST'):
        try:
            content_type = request.headers.get('Content-Type')
            if content_type:
                mime_type = content_type.split(';')
                if (mime_type[0].strip() != 'text/html'):
                    raise TypeError('bad content type')
                if (len(mime_type) > 1):
                    if (mime_type[1].strip() != 'charset=utf-8'):
                        raise TypeError('bad mime charset')
                
                post_data = request.data.decode('utf-8')
                if (not post_data):
                    raise ValueError()
                if (len(post_data.split('@')) != 2):
                    raise ValueError()
                if (len(post_data.split('@')[1].split(':')) != 2):
                    raise ValueError()

                repo_url_file = open(repo_url_filename, 'w')
                print(post_data, file=repo_url_file)
                repo_url_file.close()

                return post_data
            else:
                raise TypeError('missing content type')
        except TypeError as error:
            bad_content_type_response = jsonify({'error': 'bad content type'})
            bad_content_type_response.status_code = 415

            return bad_content_type_response
        except ValueError as error:
            bad_value_response = jsonify({'error': str(error)})
            bad_value_response.status_code = 400

            return bad_value_response
            
    else:
        bad_method_response = jsonify({'error': 'method not allowed'})
        bad_method_response.status_code = 405

        return bad_method_response 


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

    It returns a 403 error if the request is not authorized.
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
