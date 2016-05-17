/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.wss4j.policy;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.wss4j.policy.model.SupportingTokenType;

public class SP12Constants extends SPConstants {

    private static SP12Constants sp12Constants = null;

    protected SP12Constants() {
    }

    public static synchronized SP12Constants getInstance() {
        if (sp12Constants == null) {
            sp12Constants = new SP12Constants();
        }
        return sp12Constants;
    }

    public static final String SP_NS = "http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702";
    public static final String SP_PREFIX = "sp";

    public static final String WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public static final String WST_PREFIX = "wst";

    public static final QName INCLUDE_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.ATTR_INCLUDE_TOKEN, SP12Constants.SP_PREFIX);

    public static final String INCLUDE_NEVER =
            SP12Constants.SP_NS + SPConstants.INCLUDE_TOKEN_NEVER_SUFFIX;

    public static final String INCLUDE_ONCE =
            SP12Constants.SP_NS + SPConstants.INCLUDE_TOKEN_ONCE_SUFFIX;

    public static final String INCLUDE_ALWAYS_TO_RECIPIENT =
            SP12Constants.SP_NS + SPConstants.INCLUDE_TOKEN_ALWAYS_TO_RECIPIENT_SUFFIX;

    public static final String INCLUDE_ALWAYS_TO_INITIATOR =
            SP12Constants.SP_NS + SPConstants.INCLUDE_TOKEN_ALWAYS_TO_INITIATOR_SUFFIX;

    public static final String INCLUDE_ALWAYS =
            SP12Constants.SP_NS + SPConstants.INCLUDE_TOKEN_ALWAYS_SUFFIX;

    public static final QName TRUST_13 = new QName(
            SP12Constants.SP_NS, SPConstants.TRUST_13, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_CLIENT_CERTIFICATE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_CLIENT_CERTIFICATE, SP12Constants.SP_PREFIX);

    public static final QName HTTP_BASIC_AUTHENTICATION = new QName(
            SP12Constants.SP_NS, SPConstants.HTTP_BASIC_AUTHENTICATION, SP12Constants.SP_PREFIX);

    public static final QName HTTP_DIGEST_AUTHENTICATION = new QName(
            SP12Constants.SP_NS, SPConstants.HTTP_DIGEST_AUTHENTICATION, SP12Constants.SP_PREFIX);

    public static final QName TRANSPORT_BINDING = new QName(
            SP12Constants.SP_NS, SPConstants.TRANSPORT_BINDING, SP12Constants.SP_PREFIX);

    public static final QName ALGORITHM_SUITE = new QName(
            SP12Constants.SP_NS, SPConstants.ALGORITHM_SUITE, SP12Constants.SP_PREFIX);

    public static final QName LAYOUT = new QName(
            SP12Constants.SP_NS, SPConstants.LAYOUT, SP12Constants.SP_PREFIX);

    public static final QName STRICT = new QName(
            SP12Constants.SP_NS, SPConstants.LAYOUT_STRICT, SP12Constants.SP_PREFIX);

    public static final QName LAX = new QName(
            SP12Constants.SP_NS, SPConstants.LAYOUT_LAX, SP12Constants.SP_PREFIX);

    public static final QName LAXTSFIRST = new QName(
            SP12Constants.SP_NS, SPConstants.LAYOUT_LAX_TIMESTAMP_FIRST, SP12Constants.SP_PREFIX);

    public static final QName LAXTSLAST = new QName(
            SP12Constants.SP_NS, SPConstants.LAYOUT_LAX_TIMESTAMP_LAST, SP12Constants.SP_PREFIX);

    public static final QName INCLUDE_TIMESTAMP = new QName(
            SP12Constants.SP_NS, SPConstants.INCLUDE_TIMESTAMP, SP12Constants.SP_PREFIX);

    public static final QName ENCRYPT_BEFORE_SIGNING = new QName(
            SP12Constants.SP_NS, SPConstants.ENCRYPT_BEFORE_SIGNING, SP12Constants.SP_PREFIX);

    public static final QName SIGN_BEFORE_ENCRYPTING = new QName(
            SP12Constants.SP_NS, SPConstants.SIGN_BEFORE_ENCRYPTING, SP12Constants.SP_PREFIX);

    public static final QName ONLY_SIGN_ENTIRE_HEADERS_AND_BODY = new QName(
            SP12Constants.SP_NS, SPConstants.ONLY_SIGN_ENTIRE_HEADERS_AND_BODY, SP12Constants.SP_PREFIX);

    public static final QName TRANSPORT_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.TRANSPORT_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName HTTPS_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.HTTPS_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName KERBEROS_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.KERBEROS_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName SPNEGO_CONTEXT_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SPNEGO_CONTEXT_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName SECURITY_CONTEXT_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SECURITY_CONTEXT_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName SECURE_CONVERSATION_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SECURE_CONVERSATION_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName MUST_NOT_SEND_CANCEL = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_NOT_SEND_CANCEL, SP12Constants.SP_PREFIX);

    public static final QName MUST_NOT_SEND_AMEND = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_NOT_SEND_AMEND, SP12Constants.SP_PREFIX);

    public static final QName MUST_NOT_SEND_RENEW = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_NOT_SEND_RENEW, SP12Constants.SP_PREFIX);

    public static final QName SAML_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SAML_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName REL_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.REL_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName KEY_VALUE_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.KEY_VALUE_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName RSA_KEY_VALUE = new QName(
            SP12Constants.SP_NS, SPConstants.RSA_KEY_VALUE, SP12Constants.SP_PREFIX);

    public static final QName SIGNATURE_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNATURE_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName SIGNED_PARTS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_PARTS, SP12Constants.SP_PREFIX);

    public static final QName ENCRYPTED_PARTS = new QName(
            SP12Constants.SP_NS, SPConstants.ENCRYPTED_PARTS, SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ELEMENTS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_ELEMENTS, SP12Constants.SP_PREFIX);

    public static final QName XPATH_EXPR = new QName(
            SP12Constants.SP_NS, SPConstants.XPATH_EXPR, SP12Constants.SP_PREFIX);

    public static final QName ENCRYPTED_ELEMENTS = new QName(
            SP12Constants.SP_NS, SPConstants.ENCRYPTED_ELEMENTS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRED_ELEMENTS = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRED_ELEMENTS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRED_PARTS = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRED_PARTS, SP12Constants.SP_PREFIX);

    public static final QName CONTENT_ENCRYPTED_ELEMENTS = new QName(
            SP12Constants.SP_NS, SPConstants.CONTENT_ENCRYPTED_ELEMENTS, SP12Constants.SP_PREFIX);

    public static final QName USERNAME_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.USERNAME_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName WSS_USERNAME_TOKEN10 = new QName(
            SP12Constants.SP_NS, SPConstants.USERNAME_TOKEN10, SP12Constants.SP_PREFIX);

    public static final QName WSS_USERNAME_TOKEN11 = new QName(
            SP12Constants.SP_NS, SPConstants.USERNAME_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName ENCRYPTION_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.ENCRYPTION_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName X509_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.X509_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_V1_TOKEN_10 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_V1_TOKEN10, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_V3_TOKEN_10 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_V3_TOKEN10, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKCS7_TOKEN_10 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKCS7_TOKEN10, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKI_PATH_V1_TOKEN_10 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKI_PATH_V1_TOKEN10, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_V1_TOKEN_11 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_V1_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_V3_TOKEN_11 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_V3_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKCS7_TOKEN_11 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKCS7_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKI_PATH_V1_TOKEN_11 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKI_PATH_V1_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName ISSUED_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.ISSUED_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName SIGNED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName ENDORSING_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.ENDORSING_SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ENDORSING_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_ENDORSING_SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName ENCRYPTED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.ENCRYPTED_SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ENCRYPTED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_ENCRYPTED_SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName ENDORSING_ENCRYPTED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.ENDORSING_ENCRYPTED_SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName PROTECTION_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.PROTECTION_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName ASYMMETRIC_BINDING = new QName(
            SP12Constants.SP_NS, SPConstants.ASYMMETRIC_BINDING, SP12Constants.SP_PREFIX);

    public static final QName SYMMETRIC_BINDING = new QName(
            SP12Constants.SP_NS, SPConstants.SYMMETRIC_BINDING, SP12Constants.SP_PREFIX);

    public static final QName INITIATOR_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.INITIATOR_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName INITIATOR_SIGNATURE_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.INITIATOR_SIGNATURE_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName INITIATOR_ENCRYPTION_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.INITIATOR_ENCRYPTION_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName RECIPIENT_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.RECIPIENT_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName RECIPIENT_SIGNATURE_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.RECIPIENT_SIGNATURE_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName RECIPIENT_ENCRYPTION_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.RECIPIENT_ENCRYPTION_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName ENCRYPT_SIGNATURE = new QName(
            SP12Constants.SP_NS, SPConstants.ENCRYPT_SIGNATURE, SP12Constants.SP_PREFIX);

    public static final QName PROTECT_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.PROTECT_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_KEY_IDENTIFIER_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_KEY_IDENTIFIER_REFERENCE, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_ISSUER_SERIAL_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_ISSUER_SERIAL_REFERENCE, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_EMBEDDED_TOKEN_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_EMBEDDED_TOKEN_REFERENCE, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_THUMBPRINT_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_THUMBPRINT_REFERENCE, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_KEY_IDENTIFIER = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_KEY_IDENTIFIER, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_ISSUER_SERIAL = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_ISSUER_SERIAL, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_EXTERNAL_URI = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_EXTERNAL_URI, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_EMBEDDED_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_EMBEDDED_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_THUMBPRINT = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_THUMBPRINT, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_ENCRYPTED_KEY = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_ENCRYPTED_KEY, SP12Constants.SP_PREFIX);

    public static final QName WSS10 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS10, SP12Constants.SP_PREFIX);

    public static final QName WSS11 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS11, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_SIGNATURE_CONFIRMATION = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_SIGNATURE_CONFIRMATION, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_CLIENT_CHALLENGE = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_CLIENT_CHALLENGE, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_SERVER_CHALLENGE = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_SERVER_CHALLENGE, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_CLIENT_ENTROPY = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_CLIENT_ENTROPY, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_SERVER_ENTROPY = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_SERVER_ENTROPY, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_ISSUED_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_ISSUED_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_REQUEST_SECURITY_TOKEN_COLLECTION = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_REQUEST_SECURITY_TOKEN_COLLECTION, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_APPLIES_TO = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_APPLIES_TO, SP12Constants.SP_PREFIX);

    public static final QName ISSUER = new QName(
            SP12Constants.SP_NS, SPConstants.ISSUER, SP12Constants.SP_PREFIX);

    public static final QName ISSUER_NAME = new QName(
            SP12Constants.SP_NS, SPConstants.ISSUER_NAME, SP12Constants.SP_PREFIX);

    public static final QName CLAIMS = new QName(
            SP12Constants.WST_NS, SPConstants.CLAIMS, SP12Constants.WST_PREFIX);

    public static final QName REQUIRE_DERIVED_KEYS = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_DERIVED_KEYS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_IMPLIED_DERIVED_KEYS = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_IMPLIED_DERIVED_KEYS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_EXPLICIT_DERIVED_KEYS = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_EXPLICIT_DERIVED_KEYS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_EXTERNAL_URI_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_EXTERNAL_URI_REFERENCE, SP12Constants.SP_PREFIX);

    public static final QName SC13_SECURITY_CONTEXT_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SC13_SECURITY_CONTEXT_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_EXTERNAL_REFERNCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_EXTERNAL_REFERENCE, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_INTERNAL_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_INTERNAL_REFERENCE, SP12Constants.SP_PREFIX);

    public static final QName REQUEST_SECURITY_TOKEN_TEMPLATE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUEST_SECURITY_TOKEN_TEMPLATE, SP12Constants.SP_PREFIX);

    public static final QName BOOTSTRAP_POLICY = new QName(
            SP12Constants.SP_NS, SPConstants.BOOTSTRAP_POLICY, SP12Constants.SP_PREFIX);

    public static final QName XPATH = new QName(
            SP12Constants.SP_NS, SPConstants.XPATH_EXPR, SP12Constants.SP_PREFIX);

    public static final QName NO_PASSWORD = new QName(
            SP12Constants.SP_NS, SPConstants.NO_PASSWORD, SP12Constants.SP_PREFIX);

    public static final QName HASH_PASSWORD = new QName(
            SP12Constants.SP_NS, SPConstants.HASH_PASSWORD, SP12Constants.SP_PREFIX);

    public static final QName HEADER = new QName(
            SP12Constants.SP_NS, SPConstants.HEADER, SP12Constants.SP_PREFIX);

    public static final QName BODY = new QName(
            SP12Constants.SP_NS, SPConstants.BODY, SP12Constants.SP_PREFIX);

    public static final QName ATTACHMENTS = new QName(
            SP12Constants.SP_NS, SPConstants.ATTACHMENTS, SP12Constants.SP_PREFIX);


    @Override
    public IncludeTokenType getInclusionFromAttributeValue(String value) {
        if (value == null || "".equals(value)) {
            return IncludeTokenType.INCLUDE_TOKEN_ALWAYS;
        } else if (INCLUDE_ALWAYS.equals(value)) {
            return IncludeTokenType.INCLUDE_TOKEN_ALWAYS;
        } else if (INCLUDE_ALWAYS_TO_RECIPIENT.equals(value)) {
            return IncludeTokenType.INCLUDE_TOKEN_ALWAYS_TO_RECIPIENT;
        } else if (INCLUDE_ALWAYS_TO_INITIATOR.equals(value)) {
            return IncludeTokenType.INCLUDE_TOKEN_ALWAYS_TO_INITIATOR;
        } else if (INCLUDE_NEVER.equals(value)) {
            return IncludeTokenType.INCLUDE_TOKEN_NEVER;
        } else if (INCLUDE_ONCE.equals(value)) {
            return IncludeTokenType.INCLUDE_TOKEN_ONCE;
        }
        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
    }

    @Override
    public String getAttributeValueFromInclusion(IncludeTokenType value) {
        switch (value) {
            case INCLUDE_TOKEN_ALWAYS:
                return SP12Constants.INCLUDE_ALWAYS;
            case INCLUDE_TOKEN_ALWAYS_TO_RECIPIENT:
                return SP12Constants.INCLUDE_ALWAYS_TO_RECIPIENT;
            case INCLUDE_TOKEN_ALWAYS_TO_INITIATOR:
                return SP12Constants.INCLUDE_ALWAYS_TO_INITIATOR;
            case INCLUDE_TOKEN_NEVER:
                return SP12Constants.INCLUDE_NEVER;
            case INCLUDE_TOKEN_ONCE:
                return SP12Constants.INCLUDE_ONCE;
            default:
                throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
        }
    }

    @Override
    public QName getIncludeToken() {
        return INCLUDE_TOKEN;
    }

    @Override
    public QName getIssuer() {
        return ISSUER;
    }

    @Override
    public QName getIssuerName() {
        return ISSUER_NAME;
    }

    @Override
    public QName getClaims() {
        return CLAIMS;
    }

    @Override
    public QName getX509Token() {
        return X509_TOKEN;
    }

    @Override
    public QName getRequireIssuerSerialReference() {
        return REQUIRE_ISSUER_SERIAL_REFERENCE;
    }

    @Override
    public QName getRequireEmbeddedTokenReference() {
        return REQUIRE_EMBEDDED_TOKEN_REFERENCE;
    }

    @Override
    public QName getRequireThumbprintReference() {
        return REQUIRE_THUMBPRINT_REFERENCE;
    }

    @Override
    public QName getHttpsToken() {
        return HTTPS_TOKEN;
    }

    @Override
    public QName getUsernameToken() {
        return USERNAME_TOKEN;
    }

    @Override
    public QName getCreated() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getNonce() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getIssuedToken() {
        return ISSUED_TOKEN;
    }

    @Override
    public QName getRequireExternalReference() {
        return REQUIRE_EXTERNAL_REFERNCE;
    }

    @Override
    public QName getRequireInternalReference() {
        return REQUIRE_INTERNAL_REFERENCE;
    }

    @Override
    public QName getRequestSecurityTokenTemplate() {
        return REQUEST_SECURITY_TOKEN_TEMPLATE;
    }

    @Override
    public QName getKerberosToken() {
        return KERBEROS_TOKEN;
    }

    @Override
    public QName getSpnegoContextToken() {
        return SPNEGO_CONTEXT_TOKEN;
    }

    @Override
    public QName getSecurityContextToken() {
        return SECURITY_CONTEXT_TOKEN;
    }

    @Override
    public QName getRequireExternalUriReference() {
        return REQUIRE_EXTERNAL_URI_REFERENCE;
    }

    @Override
    public QName getSc13SecurityContextToken() {
        return SC13_SECURITY_CONTEXT_TOKEN;
    }

    @Override
    public QName getSc10SecurityContextToken() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getSecureConversationToken() {
        return SECURE_CONVERSATION_TOKEN;
    }

    @Override
    public QName getMustNotSendCancel() {
        return MUST_NOT_SEND_CANCEL;
    }

    @Override
    public QName getMustNotSendAmend() {
        return MUST_NOT_SEND_AMEND;
    }

    @Override
    public QName getMustNotSendRenew() {
        return MUST_NOT_SEND_RENEW;
    }

    @Override
    public QName getBootstrapPolicy() {
        return BOOTSTRAP_POLICY;
    }

    @Override
    public QName getSamlToken() {
        return SAML_TOKEN;
    }

    @Override
    public QName getRelToken() {
        return REL_TOKEN;
    }

    @Override
    public QName getRequireKeyIdentifierReference() {
        return REQUIRE_KEY_IDENTIFIER_REFERENCE;
    }

    @Override
    public QName getKeyValueToken() {
        return KEY_VALUE_TOKEN;
    }

    @Override
    public QName getRsaKeyValue() {
        return RSA_KEY_VALUE;
    }

    @Override
    public QName getSignedParts() {
        return SIGNED_PARTS;
    }

    @Override
    public QName getSignedElements() {
        return SIGNED_ELEMENTS;
    }

    @Override
    public QName getXPathExpression() {
        return XPATH_EXPR;
    }

    @Override
    public QName getXPath2Expression() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getEncryptedParts() {
        return ENCRYPTED_PARTS;
    }

    @Override
    public QName getEncryptedElements() {
        return ENCRYPTED_ELEMENTS;
    }

    @Override
    public QName getContentEncryptedElements() {
        return CONTENT_ENCRYPTED_ELEMENTS;
    }

    @Override
    public QName getRequiredElements() {
        return REQUIRED_ELEMENTS;
    }

    @Override
    public QName getRequiredParts() {
        return REQUIRED_PARTS;
    }

    @Override
    public QName getAlgorithmSuite() {
        return ALGORITHM_SUITE;
    }

    @Override
    public QName getLayout() {
        return LAYOUT;
    }

    @Override
    public QName getBody() {
        return BODY;
    }

    @Override
    public QName getAttachments() {
        return ATTACHMENTS;
    }

    @Override
    public QName getContentSignatureTransform() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getAttachmentCompleteSignatureTransform() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getHeader() {
        return HEADER;
    }

    @Override
    public QName getEncryptSignature() {
        return ENCRYPT_SIGNATURE;
    }

    @Override
    public QName getProtectTokens() {
        return PROTECT_TOKENS;
    }

    @Override
    public QName getOnlySignEntireHeadersAndBody() {
        return ONLY_SIGN_ENTIRE_HEADERS_AND_BODY;
    }

    @Override
    public QName getTransportBinding() {
        return TRANSPORT_BINDING;
    }

    @Override
    public QName getSymmetricBinding() {
        return SYMMETRIC_BINDING;
    }

    @Override
    public QName getAsymmetricBinding() {
        return ASYMMETRIC_BINDING;
    }

    @Override
    public QName getEncryptionToken() {
        return ENCRYPTION_TOKEN;
    }

    @Override
    public QName getSignatureToken() {
        return SIGNATURE_TOKEN;
    }

    @Override
    public QName getProtectionToken() {
        return PROTECTION_TOKEN;
    }

    @Override
    public QName getTransportToken() {
        return TRANSPORT_TOKEN;
    }

    @Override
    public QName getInitiatorToken() {
        return INITIATOR_TOKEN;
    }

    @Override
    public QName getInitiatorSignatureToken() {
        return INITIATOR_SIGNATURE_TOKEN;
    }

    @Override
    public QName getInitiatorEncryptionToken() {
        return INITIATOR_ENCRYPTION_TOKEN;
    }

    @Override
    public QName getRecipientToken() {
        return RECIPIENT_TOKEN;
    }

    @Override
    public QName getRecipientSignatureToken() {
        return RECIPIENT_SIGNATURE_TOKEN;
    }

    @Override
    public QName getRecipientEncryptionToken() {
        return RECIPIENT_ENCRYPTION_TOKEN;
    }

    @Override
    public QName getTrust10() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getTrust13() {
        return TRUST_13;
    }

    @Override
    public QName getScopePolicy15() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getMustSupportClientChallenge() {
        return MUST_SUPPORT_CLIENT_CHALLENGE;
    }

    @Override
    public QName getMustSupportServerChallenge() {
        return MUST_SUPPORT_SERVER_CHALLENGE;
    }

    @Override
    public QName getRequireClientEntropy() {
        return REQUIRE_CLIENT_ENTROPY;
    }

    @Override
    public QName getRequireServerEntropy() {
        return REQUIRE_SERVER_ENTROPY;
    }

    @Override
    public QName getMustSupportIssuedTokens() {
        return MUST_SUPPORT_ISSUED_TOKENS;
    }

    @Override
    public QName getRequireRequestSecurityTokenCollection() {
        return REQUIRE_REQUEST_SECURITY_TOKEN_COLLECTION;
    }

    @Override
    public QName getRequireAppliesTo() {
        return REQUIRE_APPLIES_TO;
    }

    @Override
    public QName getMustSupportInteractiveChallenge() {
        return EMPTY_QNAME;
    }

    @Override
    public QName getWss10() {
        return WSS10;
    }

    @Override
    public QName getMustSupportRefKeyIdentifier() {
        return MUST_SUPPORT_REF_KEY_IDENTIFIER;
    }

    @Override
    public QName getMustSupportRefIssuerSerial() {
        return MUST_SUPPORT_REF_ISSUER_SERIAL;
    }

    @Override
    public QName getMustSupportRefExternalUri() {
        return MUST_SUPPORT_REF_EXTERNAL_URI;
    }

    @Override
    public QName getMustSupportRefEmbeddedToken() {
        return MUST_SUPPORT_REF_EMBEDDED_TOKEN;
    }

    @Override
    public QName getWss11() {
        return WSS11;
    }

    @Override
    public QName getMustSupportRefThumbprint() {
        return MUST_SUPPORT_REF_THUMBPRINT;
    }

    @Override
    public QName getMustSupportRefEncryptedKey() {
        return MUST_SUPPORT_REF_ENCRYPTED_KEY;
    }

    @Override
    public QName getRequireSignatureConfirmation() {
        return REQUIRE_SIGNATURE_CONFIRMATION;
    }
    public enum SupportingTokenTypes implements SupportingTokenType {
        SupportingTokens(SUPPORTING_TOKENS),
        SignedSupportingTokens(SIGNED_SUPPORTING_TOKENS),
        EndorsingSupportingTokens(ENDORSING_SUPPORTING_TOKENS),
        SignedEndorsingSupportingTokens(SIGNED_ENDORSING_SUPPORTING_TOKENS),
        SignedEncryptedSupportingTokens(SIGNED_ENCRYPTED_SUPPORTING_TOKENS),
        EncryptedSupportingTokens(ENCRYPTED_SUPPORTING_TOKENS),
        EndorsingEncryptedSupportingTokens(ENDORSING_ENCRYPTED_SUPPORTING_TOKENS),
        SignedEndorsingEncryptedSupportingTokens(SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS);

        private static final Map<QName, SupportingTokenTypes> LOOKUP = new HashMap<>();

        static {
            for (SupportingTokenTypes u : EnumSet.allOf(SupportingTokenTypes.class)) {
                LOOKUP.put(u.getName(), u);
            }
        }

        public static SupportingTokenTypes lookUp(QName name) {
            return LOOKUP.get(name);
        }

        private final QName name;

        SupportingTokenTypes(QName name) {
            this.name = name;
        }

        @Override
        public QName getName() {
            return name;
        }
    }

    @Override
    @Deprecated
    public SupportingTokenType getSupportingTokenType(QName name) {
        return SupportingTokenTypes.lookUp(name);
    }
}
