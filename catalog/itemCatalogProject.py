from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"

# Connect to database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/v2.8/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
           '&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    # Extract the access token from response
    token = 'access_token=' + data['access_token']

    # Use token to get user info from API.
    url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
    http = httplib2.Http()
    result = http.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, 
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?%s&redirect=0&height=200&width=200' % token
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is avlid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's Client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Add provider to login session
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user-id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += 'img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

## Session Commit Convenience Function
def commitSession(argument):
    session.add(argument)
    session.commit()

# user Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
    commitSession(newUser)
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        #Reset the user's session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(
          json.dumps('Successfully disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# URL to clear the login session for testing
@app.route('/clearSession')
def clearSession():
  login_session.clear()
  return "Session Cleared"

# Page to handle navigation errors
@app.route('/error')
def exceptionError():
    return render_template('exception.html')

# JSON API'S to view Category Information
@app.route('/category/<int:category_id>/JSON')
def categoryJSON(category_id):
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        items = session.query(Item).filter_by(category_id=category_id).all()
        return jsonify(Items=[i.serialize for i in items])
    except:
        return render_template('exception.html')

@app.route('/category/<int:category_id>/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    try:
        category_item = session.query(Item).filter_by(id=item_id).one()
        return jsonify(category_item=category_item.serialize)
    except:
        return render_template('exception.html')

@app.route('/category/JSON')
def categoriesJSON():
    try:
        categories = session.query(Category).all()
        return jsonify(categories=[c.serialize for c in categories])
    except:
        return render_template('exception.html')

# Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
    try:
        categories = session.query(Category).order_by(asc(Category.name))
        latest_items = session.query(Item).order_by(desc(Item.id)).limit(10)
        users = session.query(User).all()
        if 'username' not in login_session:
            return render_template('publicIndex.html', categories=categories, item=latest_items)
        else:
            return render_template('index.html', categories=categories, item=latest_items, users=users)
    except:
        return render_template('exception.html')

# Add a new category
@app.route('/category/new', methods=['GET', 'POST'])
def addCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        try:
            newCategory = Category(name=request.form['name'], user_id=login_session['user_id'])
            commitSession(newCategory)
            displayCategory = session.query(Category).order_by(Category.id.desc()).first()
            return render_template('newCategory.html', newCategory=displayCategory.name)
        except:
            return render_template('exception.html')
    else:
        return render_template('newCategory.html')

# Edit a category
@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    try:
        editedCategory = session.query(Category).filter_by(id=category_id).one()
        if 'username' not in login_session:
            return redirect('/login')
        if editedCategory.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are not authorized to edit this category. Please create your own category in order to edit.');}</script><body onload='myFunction()''>"
        if request.method == "POST":
            editItem = session.query(Category).filter_by(id=category_id).first()
            editItem.name = request.form['name']
            flash('Category updated to new name, %s' % editItem.name)
            commitSession(editItem)
            return redirect(url_for('showCategories'))
        else:
            return render_template('editCategory.html', category_id=category_id)
    except:
        return render_template('exception.html')

# Delete a category
@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
def delCategory(category_id):
    try:
        catToDel = session.query(Category).filter_by(id=category_id).one()
        if 'username' not in login_session:
            return redirect('/login')
        if catToDel.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are not authorized to delete this category. Please create your own category in order to delete.');}</script><body onload='myFunction()''>"
        if request.method == "POST":
            session.delete(catToDel)
            flash('%s successfully deleted' % catToDel.name)
            session.commit()
            return redirect(url_for('showCategories'))
        else:
            return render_template('delCategory.html', category_id=category_id)
    except:
        return render_template('exception.html')

# Show all items in category
@app.route('/category/<int:category_id>/')
def showCategoryItems(category_id):
    try:
        items = session.query(Item).filter_by(category_id=category_id).all()
        categories = session.query(Category).order_by(asc(Category.name))
        def data_transmitter():
            catItem = []
            for item in items:
                catItem.append(item)
            return catItem
        data = data_transmitter()
        if 'username' not in login_session:
            return render_template('publicCategories.html', categories=categories, item=data)
        else:
            return render_template('categories.html', categories=categories, item=data)
    except:
        return render_template('exception.html')

# Add a new Item
@app.route('/category/<int:category_id>/new', methods=['GET','POST'])
def addItem(category_id):
    try:
        if 'username' not in login_session:
            return redirect('/login')
        if request.method == 'POST':
            newItem = Item(name=request.form['name'], description=request.form['description'],
                price=request.form['price'], category_id=category_id)
            commitSession(newItem)
            displayItem = session.query(Item).order_by(Item.id.desc()).first()
            return render_template('newItem.html', category_id=category_id, newItem=displayItem.name)
        else:
            return render_template('newItem.html', category_id=category_id)
    except:
        return render_template('exception.html')

# View Item Details
@app.route('/category/<int:category_id>/<int:item_id>')
def showItem(category_id, item_id):
    try:
        itemDetails = session.query(Item).filter_by(id=item_id).one()
        return render_template('itemDetails.html', category_id=category_id, item_id=item_id, 
            item_details=itemDetails)
    except:
        return render_template('exception.html')

# Edit a category item
@app.route('/category/<int:category_id>/<int:item_id>/edit', methods=['GET', 'POST'])
def editCategoryItem(category_id, item_id):
    try:
        if 'username' not in login_session:
            return redirect('/login')
        if request.method == "POST":
            try:
                itemToEdit = session.query(Item).filter_by(id=item_id).one()
                itemToEdit.name = request.form['name']
                itemToEdit.price = request.form['price']
                itemToEdit.description = request.form['description']
                commitSession(itemToEdit)
                return redirect(url_for('showCategories'))
            except:
                return render_template('exception.html')
        else:
            return render_template('editItem.html', category_id=category_id, item_id=item_id)

    except:
        return render_template('exception.html')

# Delete a category item
@app.route('/category/<int:category_id>/<int:item_id>/delete', methods=['GET', 'POST'])
def delCategoryItem(category_id, item_id):
    try:
        if 'username' not in login_session:
            return redirect('/login')
        if request.method == "POST":
            itemToDel = session.query(Item).filter_by(id=item_id).one()
            session.delete(itemToDel)
            session.commit()
            return redirect(url_for('showCategoryItems', category_id=category_id))
        else:
            return render_template('delItem.html', category_id=category_id, item_id=item_id)
    except:
        return render_template('exception.html')

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            #del login_session['gplus_id']
            #del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)