import sqlite3
import crypto
import os
import acl
import settings

'''
    This file is responsible for handling database interactions.
    The database contains two tables:
    1) the coin table, which contains the hash of all previously seen coins.
    2) and the issuer_state table, which contains the session data per user.
'''

''' ############################################################ '''
''' General DB Operations '''


def getDBconnection(filename = settings.DB_LOCATION):
    ''' Connects to the database and returns an instance of the connection '''
    conn = sqlite3.connect(filename)
    conn.text_factory = str
    cursor = conn.cursor()

    return conn, cursor


''' ############################################################ '''
''' Operations on the coin table '''


def insert2DB_Coin(coin_hash, db):
    ''' Inserts a coin hash into the coin table '''
    (conn, cur) = db
    returnStatus = 0

    try:
        param = (str(coin_hash),)
        cur.execute("""INSERT INTO coins (coin_hash) VALUES (?)""", param)
        conn.commit()
    except:
        returnStatus = -1
        conn.rollback()

    return returnStatus


def checkDB_coinExists(coin_hash, db):
    '''Queries the database to see if the coin hash exists and returns accordingly '''
    (conn, cur) = db

    param = (str(coin_hash),)
    cur.execute("""SELECT * FROM coins WHERE coin_hash=? """, param)

    numRes = len(cur.fetchall())
    retValue = False
    if numRes > 0:
        retValue = True

    return retValue


''' ############################################################ '''
''' Operations on the issuer_state table '''


def insert2DB_session(sessionid, db):
    (conn, cur) = db
    returnStatus = 0

    try:
        param = (str(sessionid),)
        cur.execute(
            """INSERT INTO issuer_state (session_id, time_stored) VALUES (?,Datetime(\'now\')) """,
            param)
        conn.commit()
    except:
        conn.rollback()
        returnStatus = -1
        print "insert2DB_session Failed"

    return returnStatus


def updateDB_validation1(sessionid, data, db):
    (conn, cur) = db
    returnStatus = 0
    (u, r1p, r2p, cp) = data

    # pack them all individually
    uEnc = str(crypto.marshall([u]))
    r1pEnc = str(crypto.marshall([r1p]))
    r2pEnc = str(crypto.marshall([r2p]))
    cpEnc = str(crypto.marshall([cp]))

    try:
        param = (uEnc, r1pEnc, r2pEnc, cpEnc, sessionid)
        cur.execute(
            """UPDATE issuer_state SET u_packed=(?),r1p_packed=(?),r2p_packed=(?),cp_packed=(?) WHERE session_id=(?) """,
            param)
        conn.commit()
    except:
        conn.rollback()
        returnStatus = -1

    return returnStatus


def sessionExists(sessionid, db):
    """Returns True if sessionid already exists """
    (conn, cur) = db

    param = (str(sessionid),)
    cur.execute("""SELECT * FROM issuer_state WHERE session_id=(?) """, param)

    numRes = len(cur.fetchall())
    retValue = False
    if numRes > 0:
        retValue = True

    return retValue


def getIssuerState(sessionid, db):
    """ This function is called by ACLValidation2 to get
		the issuer state.
		Whenever it is used, it is marked as used.
	"""
    (conn, cur) = db
    returnStatus = 0
    issuer_state = None
    try:
        param = (str(sessionid),)

        # IMPORTANT NOTE:
        # in case we are using two coins, the first one will pass this
        # and at the end of this function it will be set to 1.
        # then the next coin will see this and will attach "coin2"
        # at the end to access the second's coin data.
        # This is in line with how saving is done.
        # see service.py @ ### ACL Validation 1 ###.
        # If this doesn't happen then there is a bug
        cur.execute(
            """SELECT * FROM issuer_state WHERE session_id=(?) AND used=1""",
            param)
        numRes = len(cur.fetchall())
        if numRes > 0:
            param = (sessionid + "coin2",)

        cur.execute(
            """SELECT u_packed,r1p_packed,r2p_packed,cp_packed FROM issuer_state WHERE session_id=(?) """,
            param)

        issuer_state = acl.StateHolder()
        # TODO check query returns only one thing
        for r in cur.fetchall():
            (u,) = crypto.unmarshall(r[0])
            (r1p,) = crypto.unmarshall(r[1])
            (r2p,) = crypto.unmarshall(r[2])
            (cp,) = crypto.unmarshall(r[3])

            issuer_state.u = u
            issuer_state.r1p = r1p
            issuer_state.r2p = r2p
            issuer_state.cp = cp

        cur.execute("""UPDATE issuer_state SET used=1 WHERE session_id=(?)""",
                    param)
        conn.commit()
    except:
        conn.rollback()
        returnStatus = -1

    if returnStatus == -1:
        return -1
    else:
        return issuer_state


# ''' ############################################################ '''
# ''' Saving Functionality '''

# def dumpSQLite():
#	""" Dump the sqlite db into a file """
#
#	#dumps the sqlite file
#	os.system("sqlite3 ObliviousPayments.db .dump > ObliviousPayments.sql")
