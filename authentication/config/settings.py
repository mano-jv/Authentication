import os

# Determine environment

ENVIRONMENT = "dev"
if "ENV" in os.environ:
    ENVIRONMENT = os.environ["ENV"]

if ENVIRONMENT in ["dev", "local", "jenkins"]:
    JWKS_URL = "https://id.dev.trimble-transportation.com/oauth2/jwks/keys"
if ENVIRONMENT == "staging":
    JWKS_URL = "https://id.stg.trimble-transportation.com/oauth2/jwks/keys"
if ENVIRONMENT == "prod":
    JWKS_URL = "https://id.trimble-transportation.com/oauth2/jwks/keys"
