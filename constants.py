BASE_URL = "https://jensenlo-portfolio-project.wm.r.appspot.com"

# BOAT CONTAINTS
BOATS = "boats"
BOAT_RESULTS_PER_PAGE = 5

# LOAD CONSTANTS
LOADS = "loads"
LOAD_RESULTS_PER_PAGE = 5
LOAD_ID_ERROR = {"Error": "No load with this id exists"}
REQD_LOAD_ATTRIBUTES = ["cost", "contents", "volume"]
LOAD_ATTR_ERROR = {
    "Error": "The request object is missing at least one of the required attributes."}


# USER CONSTANTS
USERS = "users"

# ERROR CONSTANTS
ACCEPT_MEDIA_ERROR = {"Error": "Media error. Only JSON supported."}
JWT_ERROR = {"Error": "Invalid or missing JWT."}
BOAT_ID_ERROR = {"Error": "No boat with this id exists"}
PUT_ID_ERROR = {"Error": "Updating ID is forbidden."}
BOAT_OWNER_ERROR = {
    "Error": "You are not the owner of this boat; unable to perform request."}
REQD_BOAT_ATTRIBUTES = ["name", "type", "length"]
BOAT_ATTR_ERROR = {
    "Error": "The request object is missing at least one of the required attributes."}
LOAD_ON_BOAT_ERROR = {"Error": "There is already a load on this boat."}
INCORRECT_LOAD_ID = {
    "Error": "Load id passed in and load id on boat do not match."}
MEDIA_ERROR = {"Error": "Media error. Only JSON supported."}
BOAT_OWNER_ERROR = {"Error": "You are not the owner of this boat."}
NO_LOAD_ON_BOAT_ERROR = {"Error": "The boat has no load on it."}
