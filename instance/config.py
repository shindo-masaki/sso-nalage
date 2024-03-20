import os
from dotenv import load_dotenv


load_dotenv()

class Config:

    SAML_CERT_PATH = os.getenv("SAML_CERT_PATH")
    SAML_TIME_OUT = int(os.getenv("SAML_TIME_OUT"))
    SAML_ISSUER = os.getenv("SAML_ISSUER")