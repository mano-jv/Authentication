import datetime
import json

import jwt
import requests
import logging
from sci_sco_common.exceptions import error_processing
from starlette import status

from authentication.config.settings import JWKS_URL

USER_AUTH_ERROR = "Unable to decode auth info"
BAD_REQUEST = "Bad Request"
common_logger = logging.getLogger(__name__)


def get_rsa_key(request_refresh):
    """This function retrieves the rsa key to verify the signature
        on the JWT.  It can be called at initialization and by
        other functions within this module.

    Args:
        request_refresh (boolean): Try to refetch the key even if we already have it.

    Returns:
        rsa_key (cryptography.hazmat.backends.openssl.rsa._RSAPublicKey): The rsa key

    """

    newtime = datetime.datetime.now()

    # Only get the rsa key if we haven't gotten it already OR
    # if we have gotten it longer than 3 minutes ago.
    # By having a wait of 3 minutes, we prevent an attacker from
    # trying to cause to many requests for the key which could
    # slow down performance or cause other disruption due to too
    # much traffic to the server with the JWKS.
    refresh = False
    if get_rsa_key.saved_rsa_key and get_rsa_key.datetimestamp:
        if request_refresh:
            timediff = newtime - get_rsa_key.datetimestamp
            if timediff.seconds > 180:
                refresh = True
    else:
        refresh = True

    if refresh:
        # Get the key to verify the signature on the jwt
        try:
            keys = requests.get(JWKS_URL)

        except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
        ) as conn_except:
            common_logger.warning(
                {
                    "log_msg_type": "CONNECTIVITY_ISSUE",
                    "reason": "Connection error.  Failed to retrieve keys.",
                    # This tells us which error it was
                    "error_type": str(type(conn_except)),
                }
            )
            return None

        keys_dict = keys.json()
        key_list = keys_dict["keys"]

        # There is currently only one key
        key = key_list[0]
        get_rsa_key.saved_rsa_key = jwt.algorithms.RSAAlgorithm.from_jwk(
            json.dumps(key)
        )
        get_rsa_key.datetimestamp = newtime

        common_logger.info(
            {
                "log_msg_type": "JWKS_RETRIEVED",
            }
        )

    return get_rsa_key.saved_rsa_key


# Initialize static variable for our RSA key
get_rsa_key.saved_rsa_key = None
get_rsa_key.datetimestamp = None


def _log_decode_error(api, reason):
    """DO NOT CALL THIS FUNCTION from outside this module.
        This function does the logging for a jwt decode error.

    Args:
            api (str): The calling api - used for logging purposes
            reason (str): the reason for the failure

    Raises:
            error_processing.RequestProcessingException: Raised in all cases
                where the decoding fails.  The return status will be set to
                401 in those cases since we do not know the identity of the
                user.
    """
    common_logger.exception(
        {
            "log_msg_type": "AUTHORIZATION",
            "api": api,
            "action": "fail",
            "reason": reason,
        }
    )

    common_logger.exception(
        {
            "log_msg_type": "SECURITY",
            "api": api,
            "action": "fail",
            "reason": "JWT invalid signature error. Possible message tampering.",
        }
    )

    raise error_processing.RequestProcessingException(
        BAD_REQUEST,
        USER_AUTH_ERROR,
        status=status.HTTP_401_UNAUTHORIZED,
    )


def decode_jwt(request_jwt, api):
    """DO NOT CALL THIS FUNCTION from outside this module.
        This function uses an rsa key to decode the jwt from a
        request message.

    Args:
            request_jwt (jwt): The Trust Center jwt retrieved from the message header
            api (str): The calling api - used for logging purposes

    Returns:
            decoded_jwt: a jwt in a readable/usable format


    Raises:
            error_processing.RequestProcessingException: Raised in all cases
                where the decoding fails.  The return status will be set to
                401 in those cases since we do not know the identity of the
                user.

    """

    # Get the key to verfiy the signature on the jwt but don't
    # try to refresh the key if we already have one.
    rsa_key = get_rsa_key(False)

    if not rsa_key:
        common_logger.info(
            {
                "log_msg_type": "AUTHORIZATION",
                "api": api,
                "action": "fail",
                "reason": "Failed to retrieve JWKS.",
            }
        )

        raise error_processing.RequestProcessingException(
            "Authentication Failure",
            "An unknown error occurred.",
            status=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        decoded_jwt = jwt.decode(request_jwt, key=rsa_key, algorithms=["RS256"])
    except jwt.ExpiredSignatureError as jwt_error:
        common_logger.info(
            {
                "log_msg_type": "AUTHORIZATION",
                "api": api,
                "action": "fail",
                "reason": "Signature has expired",
            }
        )

        raise error_processing.RequestProcessingException(
            "Authorization Failure",
            "Signature has expired.",
            status=status.HTTP_401_UNAUTHORIZED,
        ) from jwt_error

    except jwt.InvalidTokenError:

        # In case the failure is due to a rotated key, try again to retrieve
        # the key and decode again.  This time if we fail throw an exception.
        rsa_key = get_rsa_key(True)

        # Try to decode again with the new key
        try:
            decoded_jwt = jwt.decode(request_jwt, key=rsa_key, algorithms=["RS256"])
        except jwt.InvalidTokenError:
            _log_decode_error(api, "Invalid Token Error")
        except jwt.PyJWTError:
            _log_decode_error(
                api,
                "JWT validation failed, unknown error.",
            )

    # Catch any other jwt errors not explicitly called out.
    # All other jwt errors inherit from this class.
    except jwt.PyJWTError:
        _log_decode_error(
            api,
            "JWT validation failed, unknown error.",
        )

    return decoded_jwt
