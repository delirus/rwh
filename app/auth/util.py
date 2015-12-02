from os import getpid, path, remove
from multiprocessing import Process
from signal import signal, getsignal, SIGTERM
from time import sleep
from sys import exit
#from datetime import datetime, timedelta

from sqlalchemy import desc, text

from app.auth.models import LoginSession
from app import rwh


def expire_old_sessions(db):
    session_duration = rwh.config['SESSION_DURATION']
    #session_duration = int(os.environ['SESSION_DURATION'])
    #expiration_date  = datetime.utcnow() - timedelta(seconds=session_duration)
    expired_sessions = LoginSession.query.order_by(desc(LoginSession.last_active)).filter(LoginSession.status == LoginSession.status_active).filter(LoginSession.last_active < text("NOW() - INTERVAL '%s seconds'" % session_duration))
    for login_session in expired_sessions:
        login_session.status = LoginSession.status_expired
        db.session.add(login_session)
        db.session.commit()


def start_periodic_cleanup(db, main_process_pid=-1, slave=True, scheduler_process_pid=-1, interval=-1):
    gc_pidfile = rwh.config['DBGC_PID']

    def write_pidfile(filename, pid):
        pidfile = open(filename, 'w')
        print(pid, file=pidfile)
        pidfile.close()

    main_pid = main_process_pid
    if (main_pid == -1):
        # if no other scheduler process is running (no PID file can be found)
        # then the scheduler will start in master mode
        if path.isfile(gc_pidfile):  # another scheduler is already running
            is_slave = True
        else:
            is_slave = False

        main_pid = getpid()
        scheduler_process = Process(target=start_periodic_cleanup, args=(db, main_pid, is_slave), name='rwh auth/dbgc scheduler')
        scheduler_process.start()

        if scheduler_process.pid:
            write_pidfile(gc_pidfile, main_pid)

            # install term signal handler
            original_term_signal_handler = getsignal(SIGTERM)
            def new_term_signal_handler(signal_number, current_frame):
                scheduler_process.terminate()
                remove(gc_pidfile)
                if original_term_signal_handler:
                    original_term_signal_handler()
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
            scheduler_pid = getpid()

            if slave:
                # if the scheduler process was started in slave mode it will
                # wait for the main (parent) process of current master to die
                # and then it will take over running the periodic task(s)
                # with parent process of this scheduler as the new main process
                #
                # there is always only one master scheduler process
                # that takes care of running the periodic task
                # and other scheduler processes (slaves) just sleep
                # and keep checking if the PID file exists
                #
                # every slave process checks the PID file at different time
                # and that time is based on the scheduler process PID
                while True:
                    initial_wait = (scheduler_pid - main_process_pid) % cleanup_interval
                    sleep(initial_wait)
                    if not path.isfile(gc_pidfile):
                        write_pidfile(gc_pidfile, main_process_pid)
                        break
                    sleep(cleanup_interval - initial_wait)

            while True:
                cleanup_run = Process(target=start_periodic_cleanup, args=(db, main_pid, False, scheduler_pid, cleanup_interval), name='rwh auth/dbgc task')
                cleanup_run.daemon = True # = should be killed when parent dies
                cleanup_run.start()
                cleanup_run.join()

                sleep(cleanup_interval)
        else:
            expire_old_sessions(db)
            exit(0)

