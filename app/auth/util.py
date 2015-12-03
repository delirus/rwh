from os import getpid, path, remove
from multiprocessing import Process
from signal import signal, getsignal, SIGTERM
from time import sleep
from sys import exit

from sqlalchemy import desc, text, or_

from app.auth.models import LoginSession
from app.auth.controllers import revoke_reddit_token
from app import rwh


def expire_old_sessions(db):
    """
    Finds all LoginSession in the Flask-SQLAlchemy DB (the only argument)
    that are in the "status_open", but the "last_active" time is in the past
    longer than the SESSION_DURATION, revokes their bearer token (reddit API)
    and changes their status to "status_expired".
    """
    session_duration = rwh.config['SESSION_DURATION']
    expired_sessions = db.session.query(LoginSession).order_by(desc(LoginSession.last_active)).filter(LoginSession.last_active < text("(NOW() - (INTERVAL '%s seconds'))" % session_duration)).filter(or_(LoginSession.status == text("'%s'" % LoginSession.status_active), LoginSession.status == text("'%s'" % LoginSession.status_initiating))).all()
    for login_session in expired_sessions:
        revoke_status = revoke_reddit_token(login_session)
        if (revoke_status == 204):
            login_session.status = LoginSession.status_expired
            db.session.add(login_session)
            db.session.commit()


def start_periodic_cleanup(db, main_process_pid=-1, master=False, scheduler_process_pid=-1, interval=-1):
    """
    Starts a background process that takes care of expiring login sessions
    that are inactive longer than the SESSION_DURATION interval.
    The background process starts another child background process
    to actually run the DB cleanup and then waits for the cleanup interval
    (SESSION_DURATION / 2 + 1 seconds by default) before running it again.

    The background process that is starting the cleanup task (scheduler)
    writes the parent process PID into a file (set in the app configuration)
    and sets a TERM signal handler that deletes the PID file
    and terminates the scheduler when the parent process is properly terminated.
    It also calls the original TERM signal handler not to interfere
    with the parent process' default behavior.

    The grand-child processes running the actual cleanup tasks are started
    with the "deamon" flag set to "True", which means that the subprocess module
    should attempt to terminate them when the scheduler process dies.

    This call is designed to be called during the main app module __init__
    which may be called from multiple processes (e.g. gunicorn workers) itself.
    In this case a new scheduler process is started for each new parent
    but they check for the existing PID file and if it is found they wait
    until the first scheduler process (master) dies. Every slave scheduler
    checks at different time (once per the cleanup interval) and if they see
    that the PID file is missing (original master scheduler was terminated)
    they write new pidfile with their parent process' PID and become new master.

    The only argument that needs to be given is the Flask-SQLAlchemy DB
    that will be passed to the expire_old_sessions() (periodically called task).
    """
    gc_pidfile = rwh.config['DBGC_PID']
    is_master = master

    def write_pidfile(filename, pid):
        pidfile = open(filename, 'w')
        print(pid, file=pidfile)
        pidfile.close()
        is_master = True

    main_pid = main_process_pid
    if (main_pid == -1):

        main_pid = getpid()
        scheduler_process = Process(target=start_periodic_cleanup, args=(db, main_pid, is_master), name='rwh auth/db-gc scheduler')
        scheduler_process.start()

        if scheduler_process.pid:
            # if no other scheduler process is running
            # (no PID file can be found) then new PID file is written
            # and the scheduler will start in master mode
            if (not path.isfile(gc_pidfile)):
                write_pidfile(gc_pidfile, main_pid)

            # install term signal handler
            original_term_signal_handler = getsignal(SIGTERM)
            def new_term_signal_handler(signal_number, current_frame):
                scheduler_process.terminate()
                if original_term_signal_handler:
                    original_term_signal_handler(signal_number, current_frame)
            signal(SIGTERM, new_term_signal_handler)

            return True
        else:
            return False
    else:
        if (interval == -1):
            cleanup_interval = (int(rwh.config['SESSION_DURATION']) / 2) + 1
        else:
            cleanup_interval = interval

        if (scheduler_process_pid == -1):
            def scheduler_term_signal_handler(signal_number, current_frame):
                if is_master:
                    remove(gc_pidfile)
                exit(0)
            signal(SIGTERM, scheduler_term_signal_handler)

            scheduler_pid = getpid()

            if (not is_master):
                # there is always only one master scheduler process
                # that takes care of running the periodic task
                # and other scheduler processes (slaves) just sleep
                # and keep checking if the PID file exists
                #
                # if the scheduler process was started in slave mode it will
                # wait for the main (parent) process of current master to die
                # (and deletes the PID file in the process) and then takes over
                # running the periodic task and becomes new master
                #
                # every slave process checks the PID file at different time
                # that is based on the scheduler process PID
                while True:
                    initial_wait = (scheduler_pid - main_process_pid) % cleanup_interval
                    sleep(initial_wait)
                    if (not path.isfile(gc_pidfile)):
                        write_pidfile(gc_pidfile, main_process_pid)
                        break
                    sleep(cleanup_interval - initial_wait)

            while True:
                cleanup_run = Process(target=start_periodic_cleanup, args=(db, main_pid, None, scheduler_pid, cleanup_interval), name='rwh auth/db-gc task')
                cleanup_run.daemon = True # = should be killed when parent dies
                cleanup_run.start()
                cleanup_run.join()

                sleep(cleanup_interval)
        else:
            expire_old_sessions(db)
            exit(0)

