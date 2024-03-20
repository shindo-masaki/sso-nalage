from flask import Blueprint, request, redirect, url_for, flash, render_template
from crsf import csrf
from base64 import b64decode
from lxml import etree
from concerns import SamlUtils
from signxml import XMLVerifier


app = Blueprint('saml', __name__)

@csrf.exempt
@app.route("/saml_auth", methods=["GET", "POST"])
def saml_auth():
    saml_response = request.form['SAMLResponse']
    decoded_saml_response = b64decode(saml_response)
    xml_tree = etree.fromstring(decoded_saml_response)
    root_tree = XMLVerifier().get_root(decoded_saml_response)

    if not SamlUtils.is_saml_response_status_success(xml_tree):
        flash("SAMLレスポンスのステータスが認証失敗です。（管理者へ確認してください。）")
        return redirect(url_for("index.index"))

    attributes = SamlUtils.get_saml_assertion_attirbute(xml_tree)

    auth_flag = True
    # 送信元の検証の処理
    if not SamlUtils.saml_verify_issuer(root_tree):
        flash("SAML送信元の検証に失敗しました。（管理者へ確認してください。）")
        auth_flag = False

    # 期限の検証の処理
    if not SamlUtils.saml_verify_timeout(root_tree):
        flash("SAML期限の検証に失敗しました。（管理者へ確認してください。）")
        auth_flag = False

    # 属性の検証の処理
    # if not SamlUtils.saml_verify_attrib(attributes):
    #     flash("SAML属性の検証に失敗しました。（管理者へ確認してください。）")
    #     auth_flag = False

    # ダイジェスト値の検証の処理
    if not SamlUtils.saml_verify_digest(root_tree):
        flash("SAMLダイジェスト値の検証に失敗しました。（管理者へ確認してください。）")
        auth_flag = False

    # 証明書の検証の処理(signature value)
    if not SamlUtils.saml_verify_signature(decoded_saml_response):
        flash("SAML証明書の検証に失敗しました。（管理者へ確認してください。）")
        auth_flag = False

    if not auth_flag:
        return redirect(url_for("index.index"))

    attributes_txt = ''
    for key, value in attributes.items():
        attributes_txt += key + ' : ' + value + '<br>'

    return render_template('index.html', saml_response=saml_response, decode_saml_response=decoded_saml_response, attributes_txt=attributes_txt)