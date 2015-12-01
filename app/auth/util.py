from os import getpid
from multiprocessing import Process
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


def start_periodic_cleanup(db, main_process_pid=-1, scheduler_process_pid=-1, interval=-1):
    main_pid = main_process_pid
    if (main_pid == -1):
        main_pid = getpid()
        scheduler_process = Process(target=start_periodic_cleanup, args=(db, main_pid), name='rwh auth/dbgc scheduler')
        scheduler_process.start()
    else:
        if (interval == -1):
            cleanup_interval = (int(rwh.config['SESSION_DURATION']) / 2) + 1
        else:
            cleanup_interval = interval

        if (scheduler_process_pid == -1):
            scheduler_pid = getpid()
            while True:
                cleanup_run = Process(target=start_periodic_cleanup, args=(db, main_pid, scheduler_pid, cleanup_interval), name='rwh auth/dbgc task')
                cleanup_run.daemon = True # should be killed when parent dies
                cleanup_run.start()
                cleanup_run.join()
        else:
            expire_old_sessions(db)
            sleep(cleanup_interval)
            exit(0)

