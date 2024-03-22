import calendar
from lxml import etree
from base64 import b64decode
from concerns import SamlUtils
from signxml import XMLVerifier
from datetime import datetime
from hashlib import sha1
from uuid import uuid4
from concerns.saml_utils import SamlUtils


def saml_signin():
    saml_signin_url = 'https://login.microsoftonline.com/d0bbe474-111e-4f21-ac30-71c2b8e4963f/saml2'
    _id = 'ONELOGIN_%s' % sha1(SamlUtils.to_bytes(uuid4().hex)).hexdigest()
    provider_name_str = '\n    ProviderName="sso-nalage"'
    is_passive_str = ''
    issue_instant = SamlUtils.parse_time_to_SAML(calendar.timegm(datetime.utcnow().utctimetuple()))
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

    return base_request

print(f'xml----------------------------------\n{saml_signin()}')
print(f'deflate_xml--------------------------\n{SamlUtils.deflate_encode(saml_signin())}')
parameters = {'SAMLRequest': SamlUtils.deflate_encode(saml_signin())}
parameters['RelayState'] = 'https://sso-nalage.azurewebsites.net'
saml_signin_url = 'https://login.microsoftonline.com/d0bbe474-111e-4f21-ac30-71c2b8e4963f/saml2'
print(f'request_url--------------------------\n{SamlUtils.redirect_saml(saml_signin_url, parameters)}')































# s = 'PHNhbWxwOlJlc3BvbnNlIElEPSJfNmMyMDYwNGItMThkZi00MDdhLWFiYzctZTRjYmExY2U5NjRkIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyNC0wMy0yMFQwNjowMzozMC44MTBaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zc28tbmFsYWdlLmF6dXJld2Vic2l0ZXMubmV0L3NhbWxfYXV0aCIgSW5SZXNwb25zZVRvPSJPTkVMT0dJTl9hMjJkNjFhY2ZjYjQ0NDJiYjkwZWU5MDFkZTJhOWQ0YWNhMjFkY2RjIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL3N0cy53aW5kb3dzLm5ldC9kMGJiZTQ3NC0xMTFlLTRmMjEtYWMzMC03MWMyYjhlNDk2M2YvPC9Jc3N1ZXI+PHNhbWxwOlN0YXR1cz48c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1scDpTdGF0dXM+PEFzc2VydGlvbiBJRD0iX2RkMGJkMWM5LWZiNmUtNDgwMi1hNTYxLTE2NGNlYmUyMTQwMCIgSXNzdWVJbnN0YW50PSIyMDI0LTAzLTIwVDA2OjAzOjMwLjgwNloiIFZlcnNpb249IjIuMCIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxJc3N1ZXI+aHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZDBiYmU0NzQtMTExZS00ZjIxLWFjMzAtNzFjMmI4ZTQ5NjNmLzwvSXNzdWVyPjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48UmVmZXJlbmNlIFVSST0iI19kZDBiZDFjOS1mYjZlLTQ4MDItYTU2MS0xNjRjZWJlMjE0MDAiPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxEaWdlc3RWYWx1ZT5VN1dYMlpkZjM5WS9BUDJkYmhqdUVlaTJMWkRVRkdjOStWdCtvNjJsZGxrPTwvRGlnZXN0VmFsdWU+PC9SZWZlcmVuY2U+PC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5UcittZnlEcTBlZngvWldqWDJ5SFhTdDJqZWRtKzRLT2paSTd3dkVaM0VpRGJ2YWkydUxXYTJFVlNSQm4zY0dFZnZRQ1hONVI0K0dyd2lZRGFhSzJBV096VzNiYk1JU2hKNjNYNTc2ZHNmZGdiOTZWN3lWbnNuTkY1TVRFUnhiTHVwTkdzeUZZTkxBc0I2UHFHUk13ZWhROWhhdWp0cU9XQmwxeVJSdVR0azJtRjVFRERKN1V3OGVra2RCaUFSN1Vlb2NnU2Y5eDRjanNDL1Y5ZGxxWHptNGFWRTI5SndlUTFxdWFXcFhhTXUveE5sc1plUHZlcENabjBZVGRqZmZrbThacThOYUtmNUJvQ0tGT0Mra0o1MDhNZHRualRSVk1TM0lnQWxFbDJESmdLVTV2UTk4Z0ttUDdUZE5wWDRrbGVCUld0eU5CcVk0UzZGUHlOOUQ5eUE9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJQzhEQ0NBZGlnQXdJQkFnSVFLcmFNMHJmZGhKOUhPdEd3bG1ySGZEQU5CZ2txaGtpRzl3MEJBUXNGQURBME1USXdNQVlEVlFRREV5bE5hV055YjNOdlpuUWdRWHAxY21VZ1JtVmtaWEpoZEdWa0lGTlRUeUJEWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREF6TWpBd016STFORE5hRncweU56QXpNakF3TXpJMU5ETmFNRFF4TWpBd0JnTlZCQU1US1UxcFkzSnZjMjltZENCQmVuVnlaU0JHWldSbGNtRjBaV1FnVTFOUElFTmxjblJwWm1sallYUmxNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQW9QaUtBdzVjZHR0WWRIa285QkIza2ZWdzV3N2laMkd5eWx3dENyTHE3Ykg4VVo4U3Nmd0V1djhpZm5pN0FMb2hvYVYrOFF0bHhIVDdic251L2hFQmpOQlNiOTI5UXVzcndMdGRSVHFGZEFQajN0Qzl2MHNueHIvMzBiTk1KYjdTVWVVZGcwRVdPZkE4VXFyV0lBc0dRUVgvWVZIMlpHQ3Npa05ocHpCeE96N3g5aWkzUlJHUlAraTRyR05rT21hZWtRb0RUTTdqSm5VdUJYR3UyNnJBWVNHS0ozQXpkanZCcy9wM09BelZWd2Q4amY1b1FqU3ZGVUNLMURkMmxOWSsrWHMyWDFDWEkzV3VuTXhEOWNYaDR4MERLVERhUHBjSzBDOTV5ODlvbXB6NmljTUVwZEdBYU1rK0ZzQUVla0lxTm5ZWXdXWFZIR3prY0VGSGlXS2dHUUlEQVFBQk1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQkoyTWZReHlRd0xvM1ZIai92UGQydmFuQ3d2L0JqZ241TVVvd29MQlB4N2RDeHdDTzZ4dVkrR0FRcnRVTmdTSHB4c2ZWaXowUVdqYWJKd3dDRy92ajlHcHVReEhVcnJQK3VCcFdNRHpwNXl3MFJZSmdzM3Evbm1YemdyTWFGcnJZYVNnbjY1bGRDZDJVdHRlQWJ1TWE5aFpiRG1hSU5SQkxmc29qMlo1S05HOUgvZ2FoelUveG9FZkVySlljRTVxKzZHMnJmRXJMeDRuM0hONGVST0xxZGNJSUd5SjVwYWh0NjhNVCs2RkY2YkJ2M0t6eGVQbDA2TmsvZzgvaTdsOGw1NHlzbDFoTllaY3VzeTFwQk9rdjdCVEovZTBBSVdsTGpFbDRoUzlLSkVYWll0UitHSUhnbUNLRy9zMDZ2V2l0Sko4WCt1b0s5dHNlQmJwY0NqbUg2PC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWduYXR1cmU+PFN1YmplY3Q+PE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiPmhNMkNKRVo1UEdLUmsxUnJJZ1NiZ2piWkpObnhJVVpPRlJyeGRpdjkxY3M8L05hbWVJRD48U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89Ik9ORUxPR0lOX2EyMmQ2MWFjZmNiNDQ0MmJiOTBlZTkwMWRlMmE5ZDRhY2EyMWRjZGMiIE5vdE9uT3JBZnRlcj0iMjAyNC0wMy0yMFQwNzowMzozMC41MThaIiBSZWNpcGllbnQ9Imh0dHBzOi8vc3NvLW5hbGFnZS5henVyZXdlYnNpdGVzLm5ldC9zYW1sX2F1dGgiLz48L1N1YmplY3RDb25maXJtYXRpb24+PC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyNC0wMy0yMFQwNTo1ODozMC41MThaIiBOb3RPbk9yQWZ0ZXI9IjIwMjQtMDMtMjBUMDc6MDM6MzAuNTE4WiI+PEF1ZGllbmNlUmVzdHJpY3Rpb24+PEF1ZGllbmNlPmh0dHBzOi8vc3NvLW5hbGFnZS5henVyZXdlYnNpdGVzLm5ldDwvQXVkaWVuY2U+PC9BdWRpZW5jZVJlc3RyaWN0aW9uPjwvQ29uZGl0aW9ucz48QXR0cmlidXRlU3RhdGVtZW50PjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvdGVuYW50aWQiPjxBdHRyaWJ1dGVWYWx1ZT5kMGJiZTQ3NC0xMTFlLTRmMjEtYWMzMC03MWMyYjhlNDk2M2Y8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvb2JqZWN0aWRlbnRpZmllciI+PEF0dHJpYnV0ZVZhbHVlPjAyYWQ3ZTBlLTBlMDQtNGZhNy1iMzBkLWMwNzIwZTMyYzE5YzwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9kaXNwbGF5bmFtZSI+PEF0dHJpYnV0ZVZhbHVlPumAsuiXpOOAgOiBlui1tzwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9pZGVudGl0eXByb3ZpZGVyIj48QXR0cmlidXRlVmFsdWU+aHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNWQwNWQ1YTktOGFlYi00YWM0LTgwNGMtOTllMzBjYmM4NGUyLzwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2NsYWltcy9hdXRobm1ldGhvZHNyZWZlcmVuY2VzIj48QXR0cmlidXRlVmFsdWU+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5odHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2NsYWltcy9tdWx0aXBsZWF1dGhuPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI+PEF0dHJpYnV0ZVZhbHVlPnNoaW5kb3UubWFzYWtpQHByby5oZWFkd2F0ZXJzLmNvLmpwPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5zaGluZG91Lm1hc2FraUBwcm8uaGVhZHdhdGVycy5jby5qcDwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PC9BdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyNC0wMy0xOFQwNjo0MzowOS4wNDdaIiBTZXNzaW9uSW5kZXg9Il9kZDBiZDFjOS1mYjZlLTQ4MDItYTU2MS0xNjRjZWJlMjE0MDAiPjxBdXRobkNvbnRleHQ+PEF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9BdXRobkNvbnRleHRDbGFzc1JlZj48L0F1dGhuQ29udGV4dD48L0F1dGhuU3RhdGVtZW50PjwvQXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+'
# decoded_saml_response = b64decode(s)
# xml_tree = etree.fromstring(decoded_saml_response)
# root_tree = XMLVerifier().get_root(decoded_saml_response)

# print(SamlUtils.saml_verify_issuer(root_tree))
# print(root_tree.attrib['IssueInstant'])
# print(SamlUtils.saml_verify_digest(root_tree))
# print(SamlUtils.saml_verify_signature(decoded_saml_response))
# # print((datetime.fromisoformat('2024-03-20T06:03:30Z'.replace('Z', '+00:00'))) - (datetime.fromisoformat('2024-03-20T06:03:30Z'.replace('Z', '+00:00'))).total_seconds())
# from datetime import datetime

# # datetimeオブジェクトの差分を計算し、timedeltaオブジェクトを得る
# difference = (datetime.fromisoformat('2024-03-20T06:03:30.810Z'.replace('Z', '+00:00'))) - (datetime.fromisoformat('2024-03-20T06:03:30.810Z'.replace('Z', '+00:00')))

# # timedeltaオブジェクトのtotal_seconds()メソッドを使用して秒数を取得
# print(difference.total_seconds())
