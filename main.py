from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

import constants

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# For Autho0
CLIENT_ID = 'aWmvc15tsUQuAFlokpA1XkQ5lHGJbhjK'
CLIENT_SECRET = 's-SfnQg5NytHtu2ivOPGFvJ2UAWH34ioRKB7g9bVnUADhdbiGG-V-KrXJGqpzyJ1'
DOMAIN = 'assignment-7-jensenlo.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
# Adapted from course code in Exploration - Authentication in Python


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    '''
    verify_jwt
    Used to verify the JWT in the request's Authorization header
    Adapted from course code in Exploration - Authentication in Python
    '''
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                        "description": "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                        "description": "No RSA key in JWKS"}, 401)


#########################################
#
# ROUTES FOR API
#
#########################################
@app.route('/')
def index():
    return "Please navigate to /boats to use this API"\



#########################################
#
# /boats
#
#########################################
@app.route('/boats', methods=['POST', 'GET'])
def boats_post():
    #########################################
    # POST REQUEST
    # Create a boat if the Authorization header contains a valid JWT
    #########################################
    if request.method == 'POST':
        # Check if user passed valid JWT
        try:
            payload = verify_jwt(request)
        # Return error if invalid JWT
        except:
            return (constants.JWT_ERROR, 401)

        # API only accepts JSON; if not JSON, return error
        if not request.is_json:
            return (constants.ACCEPT_MEDIA_ERROR, 415)

        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        request_content = request.get_json()

        # Verify request has all attributes required to post a boat Entity
        if not verifyAttributes(request_content, constants.REQD_BOAT_ATTRIBUTES):
            return (constants.BOAT_ATTR_ERROR, 400)

        # Create new boat if valid JWT
        new_boat = datastore.entity.Entity(key=client.key(constants.BOATS))
        new_boat.update({"name": request_content["name"],
                        "type": request_content["type"],
                         "length": request_content["length"],
                         "owner": payload["sub"],
                         "load": ""})
        client.put(new_boat)

        # Return boat and 201 status code
        new_boat = addBoatURLandSelf(new_boat)
        return (jsonify(new_boat), 201)

    #########################################
    # GET REQUEST
    # Return all boats owned by owner if valid JWT
    #########################################
    elif request.method == 'GET':
        # Check if valid JWT passed in header
        try:
            payload = verify_jwt(request)
        except:
            # Return error if invalid or missing JWT
            # Boats are related to a user, so JWT required in order to return the user's boats
            return (constants.JWT_ERROR, 401)

        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        id = payload["sub"]

        # Return all owner's boats if valid JWT
        query = client.query(kind=constants.BOATS)
        query.add_filter("owner", "=", id)  # Filter by owner id
        # If offset sent as param in request, start at that offset; otherwise, start at 0
        query_offset = int(request.args.get('offset', '0'))

        # Run query
        query_iterator = query.fetch(
            limit=constants.BOAT_RESULTS_PER_PAGE, offset=query_offset)
        pages = query_iterator.pages  # Get pages of query
        results = list(next(pages))  # Get items from iterator

        # If there is more than 1 page, then set next_url to be sent back with request
        if query_iterator.next_page_token:
            next_offset = query_offset + constants.BOAT_RESULTS_PER_PAGE
            next_url = request.base_url + \
                "?limit=5&offset=" + str(next_offset)
        else:
            next_url = None

        # Append ids of entities
        for e in results:
            e["id"] = e.key.id

        # Add self URLs
        for boat in results:
            boat = addBoatURLandSelf(boat)

        # Add next url and length of results to response
        final_response = {"boats": results}
        if next_url:
            final_response["next"] = next_url
        final_response["total_num_boats"] = len(list(query.fetch()))

        return (jsonify(final_response), 200)

    else:
        return (jsonify('Method not recogonized'), 405)


#########################################
#
# /boats/<id>
#
#########################################
@app.route('/boats/<id>', methods=['DELETE', 'PATCH', 'PUT', 'GET'])
def boats_delete(id):
    #########################################
    # DELETE REQUEST
    #########################################
    if request.method == 'DELETE':
        try:
            # Check if valid JWT passed in header
            payload = verify_jwt(request)

        except:
            # Invalid JWT or no JWT
            return (constants.JWT_ERROR, 401)

        # Get boat of id
        boat_key = client.key(constants.BOATS, int(id))
        boat = client.get(key=boat_key)

        # If boat with id does not exist, return error
        if boat is None:
            return (constants.BOAT_ID_ERROR, 404)

        # Check if the owner of the boat matches the JWT token
        if boat["owner"] != payload["sub"]:
            # Return error if token is not the owner of this boat
            return (jsonify(constants.BOAT_OWNER_ERROR), 403)

        # Check if there is a load on the boat that needs to be deleted
        if boat['load'] != '':
            load_id = boat['load']['id']
            # If load, we need to update load to not list that it is on a boat
            load_key = client.key(constants.LOADS, int(load_id))
            load = client.get(key=load_key)

            # If load exissts
            if load:
                # Update load to show it's on the boat
                load.update(
                    {"carrier": ""})
                client.put(load)

        # Otherwise, delete boat since they match
        client.delete(boat_key)
        return ('', 204)

    #########################################
    # PATCH REQUEST - partial update
    #########################################
    elif request.method == 'PATCH':
        try:
            # Check if valid JWT passed in header
            payload = verify_jwt(request)
        except:
            # Invalid JWT or no JWT
            return (constants.JWT_ERROR, 401)

        # API only accepts JSON; if not JSON, return error
        if not request.is_json:
            return (constants.ACCEPT_MEDIA_ERROR, 415)

        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Get boat data
        boat_key = client.key(constants.BOATS, int(id))
        boat = client.get(key=boat_key)

        # Get request info
        request_content = request.get_json()

        # If boat with id does not exist, return error
        if boat is None:
            return (constants.BOAT_ID_ERROR, 404)

        # Check if the owner of the boat matches the JWT token
        if boat["owner"] != payload["sub"]:
            # Return error if token is not the owner of this boat
            return (constants.BOAT_OWNER_ERROR, 403)

        # Otherwise, update the boat as owner is verified
        else:
            # If client tries to change id, return an error
            if "id" in request_content:
                return (constants.PUT_ID_ERROR, 403)

            # Update items included in body of request
            for attr, value in request_content.items():
                boat[attr] = value
            client.put(boat)

            boat = addBoatURLandSelf(boat)
            return(boat, 200)

    #########################################
    # PUT REQUEST - full update of boat attributes
    #########################################
    elif request.method == 'PUT':
        # Check if valid JWT passed in header
        try:
            payload = verify_jwt(request)
        # Invalid JWT or no JWT
        except:
            return (constants.JWT_ERROR, 401)

        # API only accepts JSON; if not JSON, return error
        if not request.is_json:
            return (constants.ACCEPT_MEDIA_ERROR, 415)

        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Get boat data
        boat_key = client.key(constants.BOATS, int(id))
        boat = client.get(key=boat_key)

        # Get request info
        request_content = request.get_json()

        # If boat with id does not exist, return error
        if boat is None:
            return (constants.BOAT_ID_ERROR, 404)

        # Check if the owner of the boat matches the JWT token
        if boat["owner"] != payload["sub"]:
            # Return error if token is not the owner of this boat
            return (constants.BOAT_OWNER_ERROR, 403)

        # Otherwise, owner is correct; continue with PUT request
        else:
            # If client tries to change id, return an error
            if "id" in request_content:
                return (constants.PUT_ID_ERROR, 403)

            # Verify request has all attributes required to update a boat Entity
            if not verifyAttributes(request_content, constants.REQD_BOAT_ATTRIBUTES):
                return (constants.BOAT_ATTR_ERROR, 400)

            # Attributes verified; update boat
            boat.update(
                {"name": request_content["name"], "type": request_content["type"], "length": request_content["length"]})
            client.put(boat)

            boat = addBoatURLandSelf(boat)
            return(boat, 200)

    #########################################
    # GET REQUEST
    #########################################
    elif request.method == 'GET':
        # Check if valid JWT passed in header
        try:
            payload = verify_jwt(request)
        # Invalid JWT or no JWT
        except:
            return (constants.JWT_ERROR, 401)

        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Search boat by id
        boat_key = client.key(constants.BOATS, int(id))
        boat = client.get(key=boat_key)

        # If boat doesn't exist, return Status 404 with Error message
        if boat is None:
            return (jsonify(constants.BOAT_ID_ERROR), 404)

        boat = addBoatURLandSelf(boat)

        return (jsonify(boat), 200)

    else:
        return jsonify(error='Method not recogonized')


#########################################
#
# /loads
#
#########################################
@app.route('/loads', methods=['POST', 'GET'])
def loads_post_get():
    #########################################
    # POST REQUEST
    # Create a load if the Authorization header contains a valid JWT
    #########################################
    if request.method == 'POST':
        # API only accepts JSON; if not JSON, return error
        if not request.is_json:
            return (constants.ACCEPT_MEDIA_ERROR, 415)

        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        request_content = request.get_json()

        # Verify request has all attributes required to PUT a load entity
        if not verifyAttributes(request_content, constants.REQD_LOAD_ATTRIBUTES):
            return (constants.LOAD_ATTR_ERROR, 400)

        new_load = datastore.entity.Entity(key=client.key(constants.LOADS))

        # Get all attributes from request body, and save the load to Datastore
        # Note that if client wants to add extra attributes, they will be added
        for attr, value in request_content.items():
            new_load[attr] = value

        # Add empty carrier attribute to load
        new_load['carrier'] = ''

        client.put(new_load)

        # Return boat and 201 status code
        new_load = addLoadURLandSelf(new_load)
        return (jsonify(new_load), 201)

    #########################################
    # GET REQUEST
    #########################################
    elif request.method == 'GET':
        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Return all loads since loads are not specific to a user
        query = client.query(kind=constants.LOADS)
        # If offset sent as param in request, start at that offset; otherwise, start at 0
        query_offset = int(request.args.get('offset', '0'))

        # Run query
        query_iterator = query.fetch(
            limit=constants.LOAD_RESULTS_PER_PAGE, offset=query_offset)
        pages = query_iterator.pages  # Get pages of query
        results = list(next(pages))  # Get items from iterator

        # If there is more than 1 page, then set next_url to be sent back with request
        if query_iterator.next_page_token:
            next_offset = query_offset + constants.LOAD_RESULTS_PER_PAGE
            next_url = request.base_url + \
                "?limit=5&offset=" + str(next_offset)
        else:
            next_url = None

        # Append ids of entities
        for e in results:
            e["id"] = e.key.id

        # Add self URLs
        for load in results:
            load = addLoadURLandSelf(load)

        # Add next url and length of results to response
        final_response = {"loads": results}
        if next_url:
            final_response["next"] = next_url
        final_response["total_num_loads"] = len(list(query.fetch()))

        return (jsonify(final_response), 200)

    else:
        return jsonify(error='Method not recogonized')


#########################################
#
# /loads/<id>
#
#########################################
@app.route('/loads/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def loads_get_patch_put(id):
    #########################################
    # GET REQUEST
    #########################################
    if request.method == 'GET':
        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Search load by id
        load_key = client.key(constants.LOADS, int(id))
        load = client.get(key=load_key)

        # If load doesn't exist, return Status 404 with Error message
        if load is None:
            return (jsonify(constants.LOAD_ID_ERROR), 404)

        load = addLoadURLandSelf(load)

        return (jsonify(load), 200)

    #########################################
    # PATCH REQUEST - partial update
    #########################################
    elif request.method == 'PATCH':
        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # API only accepts JSON; if not JSON, return error
        if not request.is_json:
            return (constants.ACCEPT_MEDIA_ERROR, 415)

        # Get load data
        load_key = client.key(constants.LOADS, int(id))
        load = client.get(key=load_key)

        # If load doesn't exist, return Status 404 with Error message
        if load is None:
            return (jsonify(constants.LOAD_ID_ERROR), 404)

        # Get request info
        request_content = request.get_json()

        # If client tries to change id, return an error
        if "id" in request_content:
            return (constants.PUT_ID_ERROR, 403)

        # Update items included in body of request
        for attr, value in request_content.items():
            load[attr] = value
        client.put(load)

        load = addLoadURLandSelf(load)
        return(load, 200)

    #########################################
    # PUT REQUEST - full update
    #########################################
    elif request.method == 'PUT':
        # API only accepts JSON; if not JSON, return error
        if not request.is_json:
            return (constants.ACCEPT_MEDIA_ERROR, 415)

        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Get load data
        load_key = client.key(constants.LOADS, int(id))
        load = client.get(key=load_key)

        # If load doesn't exist, return Status 404 with Error message
        if load is None:
            return (jsonify(constants.LOAD_ID_ERROR), 404)

        # Get request info
        request_content = request.get_json()

        # If client tries to change id, return an error
        if "id" in request_content:
            return (constants.PUT_ID_ERROR, 403)

        # Verify request has all attributes required to PUT a load entity
        if not verifyAttributes(request_content, constants.REQD_LOAD_ATTRIBUTES):
            return (constants.LOAD_ATTR_ERROR, 400)

        # Update items included in body of request
        for attr, value in request_content.items():
            load[attr] = value

        client.put(load)

        load = addLoadURLandSelf(load)
        return(load, 200)

    #########################################
    # DELETE REQUEST
    #########################################
    elif request.method == 'DELETE':
        # Get load data
        load_key = client.key(constants.LOADS, int(id))
        load = client.get(key=load_key)

        # If load doesn't exist, return Status 404 with Error message
        if load is None:
            return (jsonify(constants.LOAD_ID_ERROR), 404)

        # Check if the load is on a boat
        if load['carrier'] != '':
            boat_id = load['carrier']['id']
            # If load is on boat, we need to delete load from boat
            boat_key = client.key(constants.BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            # If boat exists
            if boat:
                # Update load to show it's on the boat
                boat.update(
                    {"load": ""})
                client.put(boat)

        # Now we can delete load
        client.delete(load)

        return ('', 204)

    else:
        return jsonify(error='Method not recogonized')


#########################################
#
# /boats/<boat_id>/loads/<load_id>
#
#########################################
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PATCH', 'DELETE'])
def boats_loads_put_delete(boat_id, load_id):
    #########################################
    # PATCH REQUEST
    #########################################
    if request.method == 'PATCH':
        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Get boat data
        boat_key = client.key(constants.BOATS, int(boat_id))
        boat = client.get(key=boat_key)

        # Get load data
        load_key = client.key(constants.LOADS, int(load_id))
        load = client.get(key=load_key)

        # If boat does not exist, return error
        if boat is None:
            return (constants.BOAT_ID_ERROR, 404)

        # If load does not exist, return error
        if load is None:
            return (constants.LOAD_ID_ERROR, 404)

        # If there is already a load on the boat, send back error
        if boat['load'] != '':
            return (jsonify(constants.LOAD_ON_BOAT_ERROR), 400)

        # Add URLs to add onto each boat and load
        boat = addBoatURLandSelf(boat)
        load = addLoadURLandSelf(load)

        # Update boat to have new load
        boat.update({"load": {'id': load.key.id,
                    'contents': load['contents'], 'volume': load['volume'], 'cost': load['cost'], 'self': load['self']}})
        client.put(boat)

        # Update load to show it's on the boat
        load.update(
            {"carrier": {'id': boat.key.id, 'name': boat['name'], 'type': boat['type'], 'length': boat['length'], 'self': boat['self']}})
        client.put(load)

        load = addLoadURLandSelf(load)
        return(load, 200)

    #########################################
    # DELETE REQUEST
    #########################################
    elif request.method == 'DELETE':
        # Get boat data
        boat_key = client.key(constants.BOATS, int(boat_id))
        boat = client.get(key=boat_key)

        # Get load data
        load_key = client.key(constants.LOADS, int(load_id))
        load = client.get(key=load_key)

        # If boat does not exist, return error
        if boat is None:
            return (constants.BOAT_ID_ERROR, 404)

        # If load does not exist, return error
        if load is None:
            return (constants.LOAD_ID_ERROR, 404)

        # Verify boat has load on it
        if boat["load"] == '':
            return (jsonify(constants.NO_LOAD_ON_BOAT_ERROR), 400)

        # If load id does not match load id on boat, return error
        if boat['load']['id'] != load.key.id:
            return (jsonify(constants.INCORRECT_LOAD_ID), 400)

        # Update boat to remove the load
        boat.update({"load": ""})
        client.put(boat)

        # Update load to show it is not on a boat
        load.update(
            {"carrier": ""})
        client.put(load)

        return('', 204)

    else:
        return jsonify(error='Method not recogonized')


#########################################
#
# /users
#
#########################################
@app.route('/users', methods=['GET'])
def get_users():
    #########################################
    # GET REQUEST
    #########################################
    if request.method == 'GET':
        # API only can send back JSON; if client cannot accept JSON, return error
        if 'application/json' not in request.accept_mimetypes:
            return (constants.MEDIA_ERROR, 406)

        # Return all users
        query = client.query(kind=constants.USERS)
        results = list(query.fetch())
        return (jsonify(results), 200)

    else:
        return jsonify(error='Method not recogonized')


#########################################
#
# /decode
# Decode the JWT supplied in the Authorization header
#########################################
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)

    # Check if user is registered as a user in the app
    query = client.query(kind=constants.USERS)
    query.add_filter("id", "=", payload['sub'])
    results = list(query.fetch())

    # If user is not currently stored, create new User entity
    if not results:
        # Create new user entity if valid JWT
        new_user = datastore.entity.Entity(key=client.key(constants.USERS))
        new_user.update(
            {'nickname': payload['nickname'], 'email': payload['email'], 'id': payload['sub']})
        client.put(new_user)

    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
# of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}


def addBoatURLandSelf(boat):
    """
    Create URL to return with Entity
    Also attaches Entity ID to object
    Note: These items are NOT saved in Datastore, only returned with Entity
    generating API response
    """
    url = constants.BASE_URL + "/boats/" + str(boat.key.id)
    boat.update({"id": str(boat.key.id), "self": url})
    return boat


def addLoadURLandSelf(load):
    """
    Create URL to return with Entity
    Also attaches Entity ID to object
    Note: These items are NOT saved in Datastore, only returned with Entity
    generating API response
    """
    url = constants.BASE_URL + "/loads/" + str(load.key.id)
    load.update({"id": str(load.key.id), "self": url})
    return load


def verifyAttributes(content, attributes):
    """
    Function to verify request Body has all necessary attributes to POST/PUT a boat Entity
    """
    # Verify request has all attributes required for a boat entity
    for attr in attributes:
        if attr not in content:
            return False
    return True


# Adapted from https://stackoverflow.com/questions/35741883/customize-the-method-not-allow-response-in-flask
@ app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'Error': "Method not allowed at this endpoint."}), 405


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
