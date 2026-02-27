# auth_strategies/constants.py

GOOGLE = "google"
GITHUB = "github"
MICROSOFT = "microsoft"

SUPPORTED_PROVIDERS = {GOOGLE, GITHUB, MICROSOFT}

# Redis key prefix for OAuth state tokens
OAUTH_STATE_PREFIX = "oauth:state:"
OAUTH_STATE_TTL_SECONDS = 600  # 10 minutes — more than enough for a login flow

# Google OAuth URLs
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


# GitHub OAuth URLs
GITHUB_AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"

# Microsoft OAuth URLs
MICROSOFT_AUTHORIZATION_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MICROSOFT_USERINFO_URL = "https://graph.microsoft.com/v1.0/me"

# Standard claim keys
CLAIM_SUB = "sub"
CLAIM_EMAIL = "email"
CLAIM_EMAIL_VERIFIED = "email_verified"
CLAIM_GIVEN_NAME = "given_name"
CLAIM_FAMILY_NAME = "family_name"
CLAIM_NAME = "name"
CLAIM_PICTURE = "picture"
