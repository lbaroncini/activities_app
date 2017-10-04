from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Activity, ActivityItem, User

app = Flask(__name__)

from flask import session as login_session
import random, string
import oauth2client
import oauth2client.client
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///activitiesapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request
# store it n the session for later validation

@app.route('/login')
def showlogin():
    print request.args.get('state')
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    print state
    return render_template('login.html', STATE = state)

# --- Google login --------
@app.route('/gconnect', methods=['POST', 'GET'])
def gconnect():
    print login_session['state']
    print request.args.get('state')
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Checking acces token validity
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # abort if errors
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # Verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Oops! Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Oops! Token's client ID doesn't match app's"), 401)
        print "Token's client ID doesn't match app's"
        response.headers['Content-Type'] = 'application/json'
        return response
    # check if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
    # Store the access token in the session
    login_session['provider'] = 'google'
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
# Make new user if it doesn't exist already

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<p>Welcome, '
    output += login_session['username']
    output += '!</p>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style= "width: 100px; height: 100px; border-radius: 150px; -webkit-border-radius: 150px; -moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

#  Disconnecting
@app.route('/gdisconnect')
def gdisconnect():
    # check if user is connected
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset user's session
        del login_session['credentials']
        del login_session['gplus_id'] 
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

# ---- FaceBook login -----
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secret.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secret.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session and login_session['provider'] == 'google':
            gdisconnect()
            flash("You have successfully been logged out.")
            return redirect(url_for('showActivities'))            
    elif 'provider' in login_session and login_session['provider'] == 'facebook':
            fbdisconnect()
            flash("You have successfully been logged out.")
            return redirect(url_for('showActivities'))
    else:
        flash("You were not logged in to begin with!")
        redirect(url_for('showActivities'))


# ---------------- Endpoint code --------------------------------------
@app.route('/JSON')
@app.route('/activities/JSON')
def showActivitiesJSON():
    acts = session.query(Activity).all()
    return jsonify(Activity =[a.serialize for a in acts])

@app.route('/activities/<int:activity_id>/JSON')
def ActivityJSON(activity_id):
    act = session.query(Activity).filter_by(id = activity_id).one()
    return jsonify( activity = act.serialize)

@app.route('/activities/<int:activity_id>/activityitems/JSON')
def showActivityItemsJSON(activity_id):
    activity = session.query(Activity).filter_by(id=activity_id).one()
    items = session.query(ActivityItem).filter_by(activity_id=activity_id).all()
    return jsonify(ActivityItem=[i.serialize for i in items])

@app.route('/activities/<int:activity_id>/activityitems/<int:activityitems_id>/JSON')
def activityItemJSON(activity_id, activityitems_id):
    activityItem = session.query(ActivityItem).filter_by(id = activityitem_id).one()
    return jsonify(Activityitem = activityItem.serialize)

## --------------------------- Ativities code -----------------------------------------
@app.route('/')
@app.route('/activities')
def showActivities():
    activity = session.query(Activity).order_by(Activity.name)
    if 'username' not in login_session:
        return render_template('publicactivities.html', activity=activity)
    else:
        return render_template('activities.html', activity = activity)

@app.route('/activities/new/', methods=['GET', 'POST'])
def newActivity():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newAct = Activity(name = request.form['name'], picture = request.form['picture'], user_id = login_session['user_id']) # added act_pic
        session.add(newAct)
        session.commit()
        flash("New Activity Successfully Created!")
        return redirect(url_for('showActivities'))
    else:
        return render_template('newactivity.html')

@app.route('/activities/<int:activity_id>/edit/', methods=['GET', 'POST'])
def editActivity(activity_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedAct = session.query(Activity).filter_by(id = activity_id).one()
    if editedAct.user_id != login_session['user_id']:
       flash("Only the creator of an activity can edit it")
       return redirect(url_for('showActivities'))
    if request.method == 'POST':
        if request.form['name']:
            editedAct.name = request.form['name']
        session.add(editedAct)
        session.commit()
        flash("Activity Successfully Edited!")
        return redirect(url_for('showActivities'))
    else:
        return render_template('editactivity.html', activity_id = activity_id, i = editedAct)

@app.route('/activities/<int:activity_id>/delete/', methods=['GET', 'POST'])
def deleteActivity(activity_id):
    if 'username' not in login_session:
        return redirect('/login')
    actToDelete = session.query(Activity).filter_by(id = activity_id).one()
    if actToDelete.user_id != login_session['user_id']:
       flash("Only the creator of an activity can delete it")
       return redirect(url_for('showActivities'))
    if request.method == 'POST':
        session.delete(actToDelete)
        items = session.query(ActivityItem).filter_by(activity_id=activity_id).all()
        for item in items:
            session.delete(item)  
        session.commit()
        flash("Activity Successfully Deleted!")
        return redirect(url_for('showActivities'))
    else:
        return render_template('deleteactivity.html', activity_id = activity_id, i = actToDelete)

## ------------------------------- Activity Items code ---------------------------------
@app.route('/activities/<int:activity_id>/activityitems')
def showActivityItems(activity_id):
    activity = session.query(Activity).filter_by(id=activity_id).one()
    creator = getUserInfo(activity.user_id)
    items = session.query(ActivityItem).filter_by(activity_id=activity_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicactivityitems.html', items=items, activity=activity, creator=creator)
    else:
        return render_template('items.html', items=items, activity=activity, creator=creator)

    # return render_template('items.html', activity = activity, items = items)

# Task 1: Create route for newActivityItem function here
@app.route('/activities/<int:activity_id>/new/', methods=['GET', 'POST'])
def newActivityItem(activity_id):
    if 'username' not in login_session:
        return redirect('/login')
    activity = session.query(Activity).filter_by(id=activity_id).one()
    if request.method == 'POST':
        newItem = ActivityItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], activity_id = activity_id, user_id = activity.user_id)
        session.add(newItem)
        session.commit()
        flash("New Activity Item Created!")
        return redirect(url_for('showActivityItems', activity_id = activity_id))
    else:
        return render_template('/newactivityitem.html', activity_id = activity_id, i = activity)

# Task 2: Create route for editActivityItem function here
@app.route('/activities/<int:activity_id>/<int:activityitems_id>/edit/', methods=['GET', 'POST'])
def editActivityItem(activity_id, activityitems_id):
    if 'username' not in login_session:
        return redirect('/login')
    activity = session.query(Activity).filter_by(id=activity_id).one()
    editedItem = session.query(ActivityItem).filter_by(id = activityitems_id).one()
    if request.method == 'POST':
        editedItem.name = request.form['name']
        editedItem.description = request.form['description']
        editedItem.price = request.form['price']
        session.add(editedItem)
        session.commit()
        flash("Activity Item Successfully Edited!")
        return redirect(url_for('showActivityItems', activity_id = activity_id))
    else:
        return render_template('editactivityitem.html', activity_id = activity_id, activityitems_id = activityitems_id, i = activity, p = editedItem)

# Task 3: Create a route for deleteActivityItem function here
@app.route('/activities/<int:activity_id>/<int:activityitems_id>/delete/', methods=['GET', 'POST'])
def deleteActivityItem(activity_id, activityitems_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(ActivityItem).filter_by(id = activityitems_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Activity Item Successfully Deleted!")
        return redirect(url_for('showActivityItems', activity_id = activity_id))
    else:
        return render_template('deleteactivityitem.html', i = itemToDelete)

def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5070)


