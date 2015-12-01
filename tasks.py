import os
from invoke import run, task, Collection

namespace = Collection()

server = Collection('server')

@task(help={'pid_file':  'PID file for gunicorn server',
            'conf_file': 'gunicorn configuration'})
def start_server(pidfile=os.environ['GUNICORN_PID'],
                 config =os.environ['GUNICORN_CONF']):
    """
    Starts DB GC and gunicorn server using the given PID- and config file.
    """
    if os.path.isfile(pidfile):
        print("A PID file for running server was found at %s.\nIf server is not running, remove the stale PID file and try again." % pidfile)
    else:
        print("Starting gunicorn server... ")
        gunicorn_start_cmd  = "gunicorn -D -p %s -c %s app:rwh" % (pidfile, config)
        run(gunicorn_start_cmd)

server.add_task(start_server, name='start')

@task(help={'pid_file': 'PID file of the running gunicorn server'})
def restart_server(pidfile=os.environ['GUNICORN_PID']):
    """
    Restarts the DB GC and gunicorn server (if it is running).
    """
    if os.path.isfile(pidfile):
        print("Restarting gunicorn server... ")
        gunicorn_restart_cmd = "if [ -n {ps -efA | grep gunicorn | awk '{print $2}' | grep `cat %s`} ]; then kill -HUP `cat %s`; else echo 'Server not running. Remove stale PID file.'; fi" % (pidfile, pidfile)
        run(gunicorn_restart_cmd)
    else:
        print("Could not find gunicorn PID file. Is server running?")

server.add_task(restart_server, name='restart')

@task(help={'pid_file': 'PID file of the running gunicorn server'})
def stop_server(pidfile=os.environ['GUNICORN_PID']):
    """
    Stops a running gunicorn server.
    """
    if os.path.isfile(pidfile):
        print("Stopping gunicorn server... ")
        gunicorn_stop_cmd = "if [ -n {ps -efA | grep gunicorn | awk '{print $2}' | grep `cat %s`} ]; then kill -TERM `cat %s`; else echo 'Server not running. Remove stale PID file.'; fi" % (pidfile, pidfile)
        run(gunicorn_stop_cmd)
    else:
        print("Could not find gunicorn PID file. Is server running?")

server.add_task(stop_server, name='stop')

namespace.add_collection(server)


db = Collection('db')

@task()
def create_tables():
    """
    Creates all tables required for app DB models.
    """
    from app import db as app_db
    app_db.create_all()

db.add_task(create_tables, name='initialize')

namespace.add_collection(db)


