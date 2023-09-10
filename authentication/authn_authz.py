import uuid

import logging
from sci_sco_common.exceptions import error_processing
from starlette import status

from authentication import auth_utils
from authentication.constants import HEADER_JWT
from authentication.decode_jwt import decode_jwt

common_logger = logging.getLogger(__name__)
USER_AUTH_ERROR = "Unable to decode auth info"
BAD_REQUEST = "Bad Request"
MISSING_AUTH_VALUES = "Malformed request missing expected authorization values"


class UserInfo:
    """The UserInfo class contains information pulled from the jwt that
    was received from TTC.

    Attributes:
        account_id (str): The TTC assigned account ID for the
                          company the user/key belongs to
        account_name (str): The name of the account, such as carrier name
        exp (str): Expiry time of the token
        identity_type (str): "user" or "application"
        sub (str): TTC user/application id
        name (str): The key name or the user's name
        email (str): The user's email address.  Not present for API key
        roles (List<str>): The roles that are assigned for the user. Not present for API key
    """

    def __init__(self):
        # All identity elements from jwt are strings even if they could be integers.
        # This allows the format to change.
        self.account_id = ""
        self.account_name = ""
        self.exp = ""
        # possible values "user" and "application"
        self.identity_type = ""
        self.sub = ""
        self.name = ""
        self.email = ""
        self.roles = []


def _get_user_info_from_jwt(request_jwt, api):
    """
        This function retrieves info from the jwt and populates the
        user_info that will be returned from authorization.

        trimble_account_id - optional
        account_id - required
        account_name - required
        identity_type - required
        name - required
        user_id - required
        email - required for user, but not for application

    Args:
            request_jwt (jwt): The TTC jwt retrieved from the message header
            api (str): The calling api - used for logging purposes

    Returns:
            user_info : the object with information about the user
                which has been sanity checked.

    Raises:
            error_processing.RequestProcessingException: Raised in all cases
                where the data does not pass sanity checks.

    """
    user_info = UserInfo()
    decoded_jwt = decode_jwt(request_jwt, api)

    try:
        original_account_id = auth_utils.strip_dangerous_characters(
            decoded_jwt["account_id"]
        )
        try:
            uuid.UUID(original_account_id)
        except (TypeError, ValueError) as error:
            common_logger.exception(
                {
                    "log_msg_type": "AUTHORIZATION",
                    "api": api,
                    "action": "fail",
                    "reason": "Account id from JWT is not a valid uuid.",
                }
            )

            raise error_processing.RequestProcessingException(
                BAD_REQUEST,
                MISSING_AUTH_VALUES,
                status=status.HTTP_401_UNAUTHORIZED,
            ) from error

        user_info.account_id = original_account_id

        user_info.account_name = auth_utils.strip_dangerous_characters(
            decoded_jwt["account_name"]
        )

        user_info.identity_type = auth_utils.strip_dangerous_characters(
            decoded_jwt["identity_type"]
        )
        if user_info.identity_type == "user":
            user_info.email = auth_utils.strip_dangerous_characters(
                decoded_jwt["email"]
            )

        user_info.name = auth_utils.strip_dangerous_characters(decoded_jwt["name"])
        user_info.sub = auth_utils.strip_dangerous_characters(
            decoded_jwt["sub"]
        )

        if "roles" in decoded_jwt:
            user_info.roles = decoded_jwt["roles"]
        user_info.exp = decoded_jwt["exp"]


    # jwt didn't have all the expected values
    except KeyError as key_error:
        auth_utils.log_bad_jwt_request(
            key_error, api, MISSING_AUTH_VALUES)

    return user_info


def _get_jwt_from_request(request, api):
    """DO NOT CALL THIS FUNCTION from outside this module.
        This function retrieves the encoded jwt from the message
        header.

    Args:
            request (jwt): The original request received
            api (str): The calling api - used for logging purposes

    Returns:
            request_jwt: a jwt in it's encoded format

    Raises:
            error_processing.RequestProcessingException: Raised in all cases
                where the decoding fails.  The return status will be set to
                401 in those cases since we do not know the identity of the
                user.

    """
    request_jwt = None

    if HEADER_JWT in request.headers:
        request_jwt = request.headers[HEADER_JWT]
    else:
        request_jwt = None

    if request_jwt is None:
        common_logger.exception(
            {
                "log_msg_type": "AUTHORIZATION",
                "api": api,
                "action": "fail",
                "reason": "JWT missing.",
            }
        )

        common_logger.exception(
            {
                "log_msg_type": "SECURITY",
                "api": api,
                "action": "fail",
                "reason": "JWT missing.  Possible malicious message.",
            }
        )
        # Returning 401 because the identity is not known.
        raise error_processing.RequestProcessingException(
            BAD_REQUEST,
            "Malformed request missing authorization information",
            status=status.HTTP_401_UNAUTHORIZED,
        )

    return request_jwt


def authorize_user(request, api):
    """This function checks if a human user or application key are authorized
        and returns their user info received in the JWT (Java Web Token) passed
        within the message header.
        They are authorized if their JWT is valid if running in TCX.  JWT
        validity is based on verification of the signature (the JWT hasn't been
        tampered with or expired).  They also must be a recognized entity type of
        developer user, customer user, trimble api key, or customer api key.

    Args:
        request (HttpRequest): The HttpRequest received by the view
        api (str): The api this method was called from, i.e., "lanes", "shippers", etc.

    Returns:
        user_info - all the information pulled from the jwt if the jwt was not
            tampered with (signature was verified).  The fields map from the
            TTC JWT as follows
            user_info.account_id = account_id (such as 2726aeda-xxxx-xxxx-xxxx-5a1c84bdf1xx)
            user_info.account_name = account_name (such as TCX-Account)
            user_info.identity_type = identity_type (user, application)
            user_info.sub = sub (such as 92cedfc6-xxxx-xxxx-xxxx-d2b5b06e91xx)
            user_info.name = name  (such as Joe Smith)
            user_info.email = email
            user_info.exp = exp
            user_info.roles = roles(such as Trimble Admin, Carrier Admin)


    Raises:
        error_processing.RequestProcessingException: This exception is raised if the
        user is not authorized
    """

    # The jwt (Java Web Token) holds all the information about the user as configured
    # in TTC
    request_jwt = _get_jwt_from_request(request, api)

    user_info = _get_user_info_from_jwt(request_jwt, api)

    return user_info
