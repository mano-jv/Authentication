import logging
from sci_sco_common.exceptions import error_processing
from starlette import status

common_logger = logging.getLogger(__name__)


def strip_dangerous_characters(input_string):
    """UTILITY FUNCTION - could be moved elsewhere if needed
    This function can be used to strip characters that
    could lead to log injection from a string.  There may be
    additional dangerous characters, but currently only log
    injection is being protected against.  In addition to the
    characters at the first link, we also remove special HTML
    characters because the logs will be viewed in datadog which
    is a web based log viewer.

    See:
    https://affinity-it-security.com/how-to-prevent-log-injection/
    https://www.tutorialspoint.com/Special-Characters-in-HTML

    Args: input_string

    Returns:
            output_string - the same string with dangerous
            characters removed.

    Raises: none.
    """

    dangerous_characters = "\r\n<>&\"'?={}\b"
    # make a copy of the string
    output_string = str(input_string)

    for character in dangerous_characters:
        output_string = output_string.replace(character, "")

    return output_string


def log_bad_jwt_request(key_error, api, error_string):
    common_logger.exception(
        {
            "log_msg_type": "AUTHORIZATION",
            "api": api,
            "action": "fail",
            "reason": "Auth info missing expected values",
        }
    )

    raise error_processing.RequestProcessingException(
        "Bad Request",
        error_string,
        status=status.HTTP_401_UNAUTHORIZED,
    ) from key_error
