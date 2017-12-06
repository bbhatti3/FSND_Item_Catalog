from flask import Flask, render_template
from flask import request, redirect, jsonify
from flask import url_for, flash
from sqlalchemy import create_engine, asc
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
from functools import wraps

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///itemCatalogApp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('/login'))
        return f(*args, **kwargs)
    return decorated_function


# Create anti-forgery state token


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


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
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
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

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Connected Already.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
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
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
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

# JSON API to view all Categories


@app.route('/api/categories/')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[e.serialize for e in categories])


# JSON API to view Category information
@app.route('/api/categories/<string:category_name>/')
def categoryJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(Items=[i.serialize for i in items])


# JSON API to view Item information
@app.route('/api/categories/<string:category_name>/<string:item_name>/')
def itemJSON(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    return jsonify(Item=item.serialize)


# Main page / Show all categories
# Please keep in mind that authentication is done in category.html
@app.route('/')
@app.route('/categories/')
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('category.html', categories=categories)


# Create a new category
@app.route('/categories/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


# Edit an existing category
@app.route('/categories/<string:category_name>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    editCategory = session.query(Category).filter_by(name=category_name).one()
    editCreator = getUserInfo(editCategory.user_id)
    if (editCreator.id != login_session['user_id']):
        flash('You are not authorized to edit this category.'
              'Please create your own category in order to edit.')
        return redirect(url_for('showCategories'))
    if request.method == 'POST':
        if request.form['name']:
            editCategory.name = request.form['name']
        session.add(editCategory)
        flash('Category Successfully Edited %s' % editCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', editCategory=editCategory)


# Delete an existing category
@app.route(
    '/categories/<string:category_name>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    deleteCategory = session.query(
        Category).filter_by(name=category_name).one()
    deleteCreator = getUserInfo(deleteCategory.user_id)
    if (deleteCreator.id != login_session['user_id']):
        flash('You are not authorized to delete this category.'
              'Please create your own category in order to delete.')
        return redirect(url_for('showCategories'))
    if request.method == 'POST':
        session.delete(deleteCategory)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('deleteCategory.html', category=deleteCategory)


# Show all items in a category
# Please keep in mind that authentication is done in category.html
@app.route('/categories/<string:category_name>/')
def showAllItems(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id)
    return render_template('category.html',
                           categories=categories,
                           category=category, items=items)


# Add a new item to a category
@app.route('/categories/<string:category_name>/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    if request.method == 'POST':
        item = Item(name=request.form['name'],
                    category_id=category.id,
                    user_id=login_session['user_id'])
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('New %s Item Successfully Created' % (item.name))
        return redirect(url_for('showAllItems', category_name=category_name))
    else:
        return render_template('newItem.html', category_name=category_name)

# Edit an existing item


@app.route('/categories/<string:category_name>/<string:item_name>/edit/',
           methods=['GET', 'POST'])
@login_required
def editItem(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    creator = getUserInfo(item.user_id)
    if (creator.id != login_session['user_id']):
        flash('You are not authorized to edit items.'
              ' Please create your own item in order to edit items.')
        return redirect(url_for('showAllItems', category_name=category_name))
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showAllItems', category_name=category_name))
    else:
        return render_template('editItem.html', category_name=category_name,
                               item=item)


# Delete an existing item
@app.route('/categories/<string:category_name>/<string:item_name>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    creator = getUserInfo(item.user_id)
    if (creator.id != login_session['user_id']):
        flash('Only the original creator can delete this item.')
        return redirect(url_for('showAllItems', category_name=category_name))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showAllItems', category_name=category_name))
    else:
        return render_template('deleteItem.html', category_name=category_name,
                               item=item)


# Show one item's name and description
# Please keep in mind that authentication is done in item.html
@app.route('/categories/<string:category_name>/<string:item_name>/')
def showItem(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    return render_template('item.html', category_name=category_name, item=item)


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect('/')
        # return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response
        # return response


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
