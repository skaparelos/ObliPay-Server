from flask import Flask, request, session
from wtforms import Form, StringField, validators
import os
import service
import database
from petlib.ec import EcGroup
import settings
import json

app=Flask(__name__)
app.secret_key = settings.FLASK_SECRET_KEY


def BL_setup(Gid = settings.SERVER_GID):
    # Parameters of the BL schemes
    G = EcGroup(Gid)
    q = G.order()
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    z = G.hash_to_point(b"z")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(2)] # 2-> hs[0], hs[1]
    return (G, q, g, h, z, hs)


params = BL_setup()


import crypto
def _loadKeys(_keys = settings.SERVER_KEYS):
    #f = open(filename, 'r')
    #_keys = f.read()
    #f.close()
    keys = crypto.unmarshall(_keys)
    return keys

keys = _loadKeys()


class ACLForm(Form):
    data = StringField('data', [validators.Length(min=100,max=4000)])


@app.route('/')
def index():
    message = ""
    if 'id' in session:
        message =  'Logged in as %s' %  (session['id'])
    #resp = make_response(render_template('index.html', message=message))
    return "Hello, world"


import base64
@app.route('/session/')
def _session():
    session['id'] = base64.b64encode(os.urandom(128))
    d = {}
    d["sessionId"] = session['id']
    return json.dumps(d)


@app.route('/acl/')
@app.route('/acl/<phase>/', methods = ['POST'])
#@app.route('/acl/<phase>/<sess_id>', methods = ['GET', 'POST'])
def acl(phase=None): 

    try:
                
        #get a db connection for each client
        dbConn, dbCursor = database.getDBconnection() 
        db = (dbConn, dbCursor)

        if phase != 'verification':
            if 'id' in session:
                session_id = session['id']
            else:
                return "-1" 
        
        form = ACLForm(request.form)
        
        if request.method != 'POST':
            return "Use POST"
    
        if phase == 'split':
            data = form.data.data
            response = service.ACLSplit(params, session_id, data, db, keys)
            dbConn.close()
            return str(response)
        elif phase == 'combine':
            data = form.data.data
            response = service.ACLCombine(params, session_id, data, db, keys)
            dbConn.close()
            return str(response)
        elif phase == 'deposit':
            data = form.data.data
            response = service.ACLDeposit(params, session_id, data, db, keys)
            dbConn.close()
            return str(response)
        elif phase == 'validation2':
            data = form.data.data
            response = service.ACLValidation2(params, session_id, data, db, keys)
            dbConn.close()
            return str(response)
        elif phase == 'verification':
            data = form.data.data
            response = service.ACLVerify(params, data, db, keys)
            dbConn.close()
            return str(response)
        elif phase == "spend":
            data = form.data.data
            response = service.ACLSpend(params, data)
            dbConn.close()
            return str(response)
        elif phase == "doubleSpent":
            data = form.data.data
            response = service.ACLDoubleSpent(params, data)
            dbConn.close()
            return str(response)
        else:
            dbConn.close()
            return "acl phase not found"

    except Exception as e:
        return(str(e))

    dbConn.close()
    return "EOFunction"


from datetime import timedelta
@app.before_request
def make_session_permanent():
    """ Make session valid for 1 minute """
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)


if __name__=="__main__":
    app.run(debug=True)
    app.run(threaded=True)
