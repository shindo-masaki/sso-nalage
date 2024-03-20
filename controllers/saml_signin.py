import calendar
from flask import Blueprint, redirect, session
from datetime import datetime
from hashlib import sha1
from uuid import uuid4
from concerns.saml_utils import SamlUtils


app = Blueprint('saml_signin', __name__)

@app.route("/saml_signin", methods=["POST"])
def saml_signin():
    saml_signin_url = 'https://login.microsoftonline.com/d0bbe474-111e-4f21-ac30-71c2b8e4963f/saml2'
    _id = 'ONELOGIN_%s' % sha1(SamlUtils.to_bytes(uuid4().hex)).hexdigest()
    provider_name_str = '\n    ProviderName="sso-nalage"'
    is_passive_str = ''
    issue_instant = SamlUtils.parse_time_to_SAML(calendar.timegm(datetime.utcnow().utctimetuple()))
    session["request_time"] = issue_instant
    sp_assert_url = 'https://sso-nalage.azurewebsites.net/saml_auth'
    sp_entity_id = 'https://sso-nalage.azurewebsites.net'
    subject_str = ''
    nameid_policy_str = '\n    <samlp:NameIDPolicy\n        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"\n        AllowCreate="true" />'
    requested_authn_context_str = '    <samlp:RequestedAuthnContext Comparison="exact">\n        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n    </samlp:RequestedAuthnContext>'
    base_request = SamlUtils.AUTHN_REQUEST % \
        {
            'id': _id,
            'provider_name': provider_name_str,
            'force_authn_str': '',# false or Falseを試す
            'is_passive_str': is_passive_str,
            'issue_instant': issue_instant,
            'destination': saml_signin_url,
            'assertion_url': sp_assert_url,
            'entity_id': sp_entity_id,
            'subject_str': subject_str,
            'nameid_policy_str': nameid_policy_str,
            'requested_authn_context_str': requested_authn_context_str,# この項目を削除して試す
            'attr_consuming_service_str': '',
            'acs_binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        }
    saml_requet = SamlUtils.deflate_encode(base_request)
    parameters = {'SAMLRequest': saml_requet}
    parameters['RelayState'] = 'https://sso-nalage.azurewebsites.net'
    url = SamlUtils.redirect_saml(saml_signin_url, parameters)

    return redirect(url)
