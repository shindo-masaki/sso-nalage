import re, zlib
from flask import session
from datetime import datetime
from urllib.parse import quote_plus
from instance.config import Config
from typing import FrozenSet
from lxml import etree
from base64 import b64decode, b64encode
from signxml import XMLVerifier
from signxml.util import ds_tag
from signxml.verifier import SignatureConfiguration
from signxml.algorithms import DigestAlgorithm, digest_algorithm_implementations
from cryptography.hazmat.bindings._rust import openssl as rust_openssl


class SamlUtils:
    AUTHN_REQUEST = """\
    <samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="%(id)s"
        Version="2.0"%(provider_name)s%(force_authn_str)s%(is_passive_str)s
        IssueInstant="%(issue_instant)s"
        Destination="%(destination)s"
        ProtocolBinding="%(acs_binding)s"
        AssertionConsumerServiceURL="%(assertion_url)s"%(attr_consuming_service_str)s>
            <saml:Issuer>%(entity_id)s</saml:Issuer>%(subject_str)s%(nameid_policy_str)s
        %(requested_authn_context_str)s
    </samlp:AuthnRequest>
    """

    LOGOUT_REQUEST = """\
    <samlp:LogoutRequest
        xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        ID="%(id)s"
        Version="2.0"
        IssueInstant="%(issue_instant)s"
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://symprest-sso.azurewebsites.net</Issuer>
        <NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"> Uz2Pqz1X7pxe4XLWxV9KJQ+n59d573SepSAkuYKSde8=</NameID>
    </samlp:LogoutRequest>
    """

    TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    @classmethod
    def to_bytes(cls, data):
        if isinstance(data, str):
            return data.encode("utf8")
        return bytes(data)

    @classmethod
    def to_string(cls, data):
        if isinstance(data, bytes):
            return data.decode("utf8")
        return str(data)

    @classmethod
    def parse_time_to_SAML(cls, time):
        data = datetime.utcfromtimestamp(float(time))
        return data.strftime(SamlUtils.TIME_FORMAT)

    @classmethod
    def check_settings(cls, settings):
        assert isinstance(settings, dict)

        errors = []
        if not isinstance(settings, dict) or len(settings) == 0:
            errors.append('invalid_syntax')
        else:
            sp_errors = []
            errors += sp_errors

        return errors

    @classmethod
    def escape_url(cls, url, lowercase_urlencoding=False):
        encoded = quote_plus(url)
        return re.sub(r"%[A-F0-9]{2}", lambda m: m.group(0).lower(), encoded) if lowercase_urlencoding else encoded

    @classmethod
    def redirect_saml(cls, url, parameters={}):
        assert isinstance(url, str)
        assert isinstance(parameters, dict)

        if url.find('?') < 0:
            param_prefix = '?'
        else:
            param_prefix = '&'

        for name, value in parameters.items():
            param = SamlUtils.escape_url(name) + '=' +  SamlUtils.escape_url(value)
            if param:
                url += param_prefix + param
                param_prefix = '&'

        return url

    @classmethod
    def deflate_encode(cls, value):
        return b64encode(SamlUtils.to_bytes(zlib.compress(SamlUtils.to_bytes(value))[2:-4]))

    @classmethod
    def is_saml_response_status_success(cls, xml_tree):
        statuses = xml_tree.findall('.//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
        for status in statuses:
            if 'urn:oasis:names:tc:SAML:2.0:status:Success' == status.attrib['Value']:
                return True

        return False

    @classmethod
    def get_saml_assertion_attirbute(cls, xml_tree):
        attribute_statement = xml_tree.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement")

        attributes = {}
        attributeList = attribute_statement.findall("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
        for attribute in attributeList:
            attribute_name = attribute.get("Name")
            attribute_value = attribute.find("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue").text
            attributes[attribute_name] = attribute_value

        return attributes

    @classmethod
    def saml_verify_timeout(cls, root_tree):
        request_time = session["request_time"]
        response_time = root_tree.attrib['IssueInstant']

        return SamlUtils.__saml_time_difference(request_time, response_time)

    @classmethod
    def saml_verify_attrib(cls, attributes):
        system_attrib_list = list(map(lambda s: s.strip(), Config.SAML_ATTRIBUTES.split(',')))
        response_attrib_list = list(map(lambda s: s.strip(), list(attributes.keys())))

        return system_attrib_list == response_attrib_list

    @classmethod
    def saml_verify_issuer(cls, root_tree):
        issuer = root_tree.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").text

        return issuer == Config.SAML_ISSUER

    @classmethod
    def __saml_time_difference(cls, start_time, end_time):
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))

        time_diff_seconds = (end_datetime - start_datetime).total_seconds()

        return time_diff_seconds < Config.SAML_TIME_OUT

    @classmethod
    def saml_verify_digest(cls, root_tree):
        config = SignatureConfiguration()
        signature_ref = SamlUtils.__get_signature(root_tree, config)
        signature = XMLVerifier()._fromstring(XMLVerifier()._tostring(signature_ref))
        signed_info = XMLVerifier()._find(signature, "SignedInfo")
        reference = XMLVerifier()._findall(signed_info, "Reference")[0]

        return SamlUtils.__verify_reference(reference, root_tree, config, None)

    @classmethod
    def saml_verify_signature(cls, decoded_saml_response):
        decode_string = decoded_saml_response.decode(encoding="utf-8")
        root_node = etree.fromstring(decode_string)
        found = root_node.findall(".//{*}X509Certificate")
        if not found:
            return False
        cert = found[0].text

        response_cert_flg = False
        try:
            XMLVerifier().verify(decode_string, x509_cert=cert)
            response_cert_flg = True
        except Exception:
            return False

        with open(Config.SAML_CERT_PATH, "r") as file:
            cert = file.read()

        file_cert_flg = False
        try:
            XMLVerifier().verify(decode_string, x509_cert=cert)
            file_cert_flg = True
        except Exception:
            return False

        return response_cert_flg and file_cert_flg

    @classmethod
    def __get_digest(cls, data, algorithm):
        algorithm_implementation = digest_algorithm_implementations[algorithm]()
        hasher = rust_openssl.hashes.Hash(algorithm=algorithm_implementation)
        hasher.update(data)
        return hasher.finalize()

    @classmethod
    def __get_signature(cls, root, config):
        if root.tag == ds_tag("Signature"):
            return root
        else:
            return XMLVerifier()._find(root, "Signature", xpath=config.location)

    @classmethod
    def __verify_reference(cls, reference, root, config, uri_resolver):
        copied_root = XMLVerifier()._fromstring(XMLVerifier()._tostring(root))
        copied_signature_ref = SamlUtils.__get_signature(copied_root, config)
        transforms = XMLVerifier()._find(reference, "Transforms", require=False)
        digest_method_alg_name = XMLVerifier()._find(reference, "DigestMethod").get("Algorithm")
        digest_value = XMLVerifier()._find(reference, "DigestValue")
        payload = XMLVerifier()._resolve_reference(copied_root, reference, uri_resolver=uri_resolver)
        payload_c14n = XMLVerifier()._apply_transforms(payload, transforms_node=transforms, signature=copied_signature_ref)
        digest_alg = DigestAlgorithm(digest_method_alg_name)
        digest_algorithms: FrozenSet[DigestAlgorithm] = frozenset(da for da in DigestAlgorithm if "SHA1" not in da.name)

        if digest_alg not in digest_algorithms:
            raise Exception(f"Digest algorithm {digest_alg.name} forbidden by configuration")
        if b64decode(digest_value.text) != SamlUtils.__get_digest(payload_c14n, digest_alg):
            return False
        return True
