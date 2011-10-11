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
package org.swssf.wss.ext;

import org.swssf.xmlsec.ext.XMLSecurityConstants;

import javax.xml.namespace.QName;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * WSSConstants for global use
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSConstants extends XMLSecurityConstants {

    protected WSSConstants() {
    }

    public static final String TIMESTAMP_PROCESSED = "TimestampProcessed";

    public static final String NS_WSSE10 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String NS_WSSE11 = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
    public static final String NS_WSU10 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String NS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope";

    public static final String NS_WST = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public static final String NS_WSC_SCT = "http://schemas.xmlsoap.org/ws/2005/02/sc/sct";

    public static final String NS_SAML = "urn:oasis:names:tc:SAML:1.0:assertion";
    public static final String NS_SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion";

    public static final String PREFIX_SOAPENV = "env";
    public static final String TAG_soap_Envelope_LocalName = "Envelope";
    public static final String TAG_soap_Header_LocalName = "Header";
    public static final String TAG_soap_Body_LocalName = "Body";

    public static final QName TAG_soap11_Envelope = new QName(NS_SOAP11, TAG_soap_Envelope_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap11_Header = new QName(NS_SOAP11, TAG_soap_Header_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap11_Body = new QName(NS_SOAP11, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
    public static final QName ATT_soap11_Actor = new QName(NS_SOAP11, "actor", PREFIX_SOAPENV);

    public static final QName TAG_soap12_Envelope = new QName(NS_SOAP12, TAG_soap_Envelope_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap12_Header = new QName(NS_SOAP12, TAG_soap_Header_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap12_Body = new QName(NS_SOAP12, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
    public static final QName ATT_soap12_Role = new QName(NS_SOAP12, "role", PREFIX_SOAPENV);

    public static final String PREFIX_WSSE = "wsse";
    public static final String PREFIX_WSSE11 = "wsse11";
    public static final QName TAG_wsse_Security = new QName(NS_WSSE10, "Security", PREFIX_WSSE);

    public static final QName TAG_wsse_SecurityTokenReference = new QName(NS_WSSE10, "SecurityTokenReference", PREFIX_WSSE);
    public static final QName TAG_wsse_Reference = new QName(NS_WSSE10, "Reference", PREFIX_WSSE);
    public static final QName ATT_wsse_Usage = new QName(NS_WSSE10, "Usage", PREFIX_WSSE);
    public static final QName ATT_wsse11_TokenType = new QName(NS_WSSE11, "TokenType", PREFIX_WSSE11);

    public static final QName TAG_wsse_KeyIdentifier = new QName(NS_WSSE10, "KeyIdentifier", PREFIX_WSSE);
    public static final QName ATT_NULL_EncodingType = new QName(null, "EncodingType");
    public static final QName ATT_NULL_ValueType = new QName(null, "ValueType");

    public static final QName TAG_wsse_BinarySecurityToken = new QName(NS_WSSE10, "BinarySecurityToken", PREFIX_WSSE);
    public static final String PREFIX_WSU = "wsu";
    public static final QName ATT_wsu_Id = new QName(NS_WSU10, "Id", PREFIX_WSU);

    public static final QName TAG_wsse11_EncryptedHeader = new QName(NS_WSSE11, "EncryptedHeader", PREFIX_WSSE11);

    public static final QName TAG_wsse_TransformationParameters = new QName(NS_WSSE10, "TransformationParameters", PREFIX_WSSE);

    public static final QName TAG_wsu_Timestamp = new QName(NS_WSU10, "Timestamp", PREFIX_WSU);
    public static final QName TAG_wsu_Created = new QName(NS_WSU10, "Created", PREFIX_WSU);
    public static final QName TAG_wsu_Expires = new QName(NS_WSU10, "Expires", PREFIX_WSU);

    public static final String NS10_SOAPMESSAGE_SECURITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";
    public static final String NS11_SOAPMESSAGE_SECURITY = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1";

    public static final String NS_X509TOKEN_PROFILE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";

    public static final String NS_X509_V3_TYPE = NS_X509TOKEN_PROFILE + "#X509v3";
    public static final String NS_X509PKIPathv1 = NS_X509TOKEN_PROFILE + "#X509PKIPathv1";
    public static final String NS_X509SubjectKeyIdentifier = NS_X509TOKEN_PROFILE + "#X509SubjectKeyIdentifier";
    public static final String NS_THUMBPRINT = NS11_SOAPMESSAGE_SECURITY + "#ThumbprintSHA1";

    public static final String SOAPMESSAGE_NS10_BASE64_ENCODING = NS10_SOAPMESSAGE_SECURITY + "#Base64Binary";

    public static final QName TAG_wsse_UsernameToken = new QName(NS_WSSE10, "UsernameToken", PREFIX_WSSE);
    public static final QName TAG_wsse_Username = new QName(NS_WSSE10, "Username", PREFIX_WSSE);
    public static final QName TAG_wsse_Password = new QName(NS_WSSE10, "Password", PREFIX_WSSE);
    public static final QName TAG_wsse_Nonce = new QName(NS_WSSE10, "Nonce", PREFIX_WSSE);
    public static final QName TAG_wsse11_Salt = new QName(NS_WSSE11, "Salt", PREFIX_WSSE11);
    public static final QName TAG_wsse11_Iteration = new QName(NS_WSSE11, "Iteration", PREFIX_WSSE11);

    public static final String NS_USERNAMETOKEN_PROFILE11 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0";
    public static final String NS_PASSWORD_DIGEST = NS_USERNAMETOKEN_PROFILE11 + "#PasswordDigest";
    public static final String NS_PASSWORD_TEXT = NS_USERNAMETOKEN_PROFILE11 + "#PasswordText";
    public static final String NS_USERNAMETOKEN_PROFILE_UsernameToken = NS_USERNAMETOKEN_PROFILE11 + "#UsernameToken";

    public static final QName TAG_wsse11_SignatureConfirmation = new QName(NS_WSSE11, "SignatureConfirmation", PREFIX_WSSE11);
    public static final QName ATT_NULL_Value = new QName(null, "Value");

    public static final String NS_C14N_EXCL = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String PREFIX_C14N_EXCL = "c14nEx";

    public static final QName TAG_wst_BinarySecret = new QName(NS_WST, "BinarySecret");

    public static final String SOAPMESSAGE_NS10_STRTransform = NS10_SOAPMESSAGE_SECURITY + "#STR-Transform";

    public static final QName TAG_saml_Assertion = new QName(NS_SAML, "Assertion");
    public static final QName TAG_saml2_Assertion = new QName(NS_SAML2, "Assertion");

    public static final String NS_SAML10_TOKEN_PROFILE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0";
    public static final String NS_SAML11_TOKEN_PROFILE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1";
    public static final String NS_SAML10_TYPE = NS_SAML10_TOKEN_PROFILE + "#SAMLAssertionID";
    public static final String NS_SAML20_TYPE = NS_SAML11_TOKEN_PROFILE + "#SAMLID";
    public static final String NS_SAML11_TOKEN_PROFILE_TYPE = NS_SAML11_TOKEN_PROFILE + "#SAMLV1.1";
    public static final String NS_SAML20_TOKEN_PROFILE_TYPE = NS_SAML11_TOKEN_PROFILE + "#SAMLV2.0";

    public static final QName ATT_NULL_AssertionID = new QName(null, "AssertionID");
    public static final QName ATT_NULL_ID = new QName(null, "ID");


    public static final String NS_WSC_05_02 = "http://schemas.xmlsoap.org/ws/2005/02/sc";
    public static final String NS_WSC_05_12 = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512";
    public static final String PREFIX_WSC = "wsc";

    public static final QName TAG_wsc0502_SecurityContextToken = new QName(NS_WSC_05_02, "SecurityContextToken", PREFIX_WSC);
    public static final QName TAG_wsc0512_SecurityContextToken = new QName(NS_WSC_05_12, "SecurityContextToken", PREFIX_WSC);
    public static final QName TAG_wsc0502_Identifier = new QName(NS_WSC_05_02, "Identifier", PREFIX_WSC);
    public static final QName TAG_wsc0512_Identifier = new QName(NS_WSC_05_12, "Identifier", PREFIX_WSC);

    public static final QName TAG_wsc0502_DerivedKeyToken = new QName(NS_WSC_05_02, "DerivedKeyToken", PREFIX_WSC);
    public static final QName TAG_wsc0512_DerivedKeyToken = new QName(NS_WSC_05_12, "DerivedKeyToken", PREFIX_WSC);
    public static final QName TAG_wsc0502_Properties = new QName(NS_WSC_05_02, "Properties", PREFIX_WSC);
    public static final QName TAG_wsc0512_Properties = new QName(NS_WSC_05_02, "Properties", PREFIX_WSC);
    public static final QName TAG_wsc0502_Length = new QName(NS_WSC_05_02, "Length", PREFIX_WSC);
    public static final QName TAG_wsc0512_Length = new QName(NS_WSC_05_02, "Length", PREFIX_WSC);
    public static final QName TAG_wsc0502_Generation = new QName(NS_WSC_05_02, "Generation", PREFIX_WSC);
    public static final QName TAG_wsc0512_Generation = new QName(NS_WSC_05_02, "Generation", PREFIX_WSC);
    public static final QName TAG_wsc0502_Offset = new QName(NS_WSC_05_02, "Offset", PREFIX_WSC);
    public static final QName TAG_wsc0512_Offset = new QName(NS_WSC_05_02, "Offset", PREFIX_WSC);
    public static final QName TAG_wsc0502_Label = new QName(NS_WSC_05_02, "Label", PREFIX_WSC);
    public static final QName TAG_wsc0512_Label = new QName(NS_WSC_05_02, "Label", PREFIX_WSC);
    public static final QName TAG_wsc0502_Nonce = new QName(NS_WSC_05_02, "Nonce", PREFIX_WSC);
    public static final QName TAG_wsc0512_Nonce = new QName(NS_WSC_05_02, "Nonce", PREFIX_WSC);

    public static final String P_SHA_1 = "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1";
    public static final String P_SHA_1_2005_12 = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1";
    public static final String WS_SecureConversation_DEFAULT_LABEL = "WS-SecureConversation";

    public static final String NS_WSS_ENC_KEY_VALUE_TYPE = NS11_SOAPMESSAGE_SECURITY + "#EncryptedKey";

    public static final String PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE = "PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE";
    public static final String PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION = "PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION";
    public static final String PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY = "PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY";
    public static final String PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY = "PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY";
    public static final String PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN = "PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN";

    public static final String PROP_TIMESTAMP_SECURITYEVENT = "PROP_TIMESTAMP";

    public static final String PROP_APPEND_SIGNATURE_ON_THIS_ID = "PROP_APPEND_SIGNATURE_ON_THIS_ID";

    /**
     * Length of UsernameToken derived key used by .NET WSE to sign a message.
     */
    public static final int WSE_DERIVED_KEY_LEN = 16;
    public static final String LABEL_FOR_DERIVED_KEY = "WS-Security";

    public static final Action SIGNATURE = new Action(XMLSecurityConstants.SIGNATURE.toString());
    public static final Action ENCRYPT = new Action(XMLSecurityConstants.ENCRYPT.toString());
    public static final Action TIMESTAMP = new Action("TIMESTAMP");
    public static final Action USERNAMETOKEN = new Action("USERNAMETOKEN");
    public static final Action USERNAMETOKEN_SIGNED = new Action("USERNAMETOKEN_SIGNED");
    public static final Action SIGNATURE_CONFIRMATION = new Action("SIGNATURE_CONFIRMATION");
    public static final Action SIGNATURE_WITH_DERIVED_KEY = new Action("SIGNATURE_WITH_DERIVED_KEY");
    public static final Action ENCRYPT_WITH_DERIVED_KEY = new Action("ENCRYPT_WITH_DERIVED_KEY");
    public static final Action SAML_TOKEN_SIGNED = new Action("SAML_TOKEN_SIGNED");
    public static final Action SAML_TOKEN_UNSIGNED = new Action("SAML_TOKEN_UNSIGNED");

    public static class Action extends XMLSecurityConstants.Action {
        protected Action(String name) {
            super(name);
        }
    }

    public static final KeyUsage Sym_Sig = new KeyUsage(XMLSecurityConstants.Sym_Sig.toString());
    public static final KeyUsage Asym_Sig = new KeyUsage(XMLSecurityConstants.Asym_Sig.toString());
    public static final KeyUsage Enc = new KeyUsage(XMLSecurityConstants.Enc.toString());
    public static final KeyUsage Dig = new KeyUsage("Dig");
    public static final KeyUsage Sym_Key_Wrap = new KeyUsage("Sym_Key_Wrap");
    public static final KeyUsage Asym_Key_Wrap = new KeyUsage("Asym_Key_Wrap");
    public static final KeyUsage Comp_Key = new KeyUsage("Comp_Key");
    public static final KeyUsage Enc_KD = new KeyUsage("Enc_KD");
    public static final KeyUsage Sig_KD = new KeyUsage("Sig_KD");
    public static final KeyUsage C14n = new KeyUsage("C14n");
    public static final KeyUsage Soap_Norm = new KeyUsage("Soap_Norm");
    public static final KeyUsage STR_Trans = new KeyUsage("STR_Trans");
    public static final KeyUsage XPath = new KeyUsage("XPath");

    public static class KeyUsage extends XMLSecurityConstants.KeyUsage {
        protected KeyUsage(String name) {
            super(name);
        }
    }

    public static final TokenType EncryptedKeyToken = new TokenType("EncryptedKeyToken");
    public static final TokenType X509V3Token = new TokenType("X509V3Token");
    public static final TokenType X509V1Token = new TokenType("X509V1Token");
    public static final TokenType X509Pkcs7Token = new TokenType("X509Pkcs7Token");
    public static final TokenType X509PkiPathV1Token = new TokenType("X509PkiPathV1Token");
    public static final TokenType UsernameToken = new TokenType("UsernameToken");
    public static final TokenType SecurityContextToken = new TokenType("SecurityContextToken");
    public static final TokenType Saml10Token = new TokenType("Saml10Token");
    public static final TokenType Saml11Token = new TokenType("Saml11Token");
    public static final TokenType Saml20Token = new TokenType("Saml20Token");
    public static final TokenType IssuedToken = new TokenType("IssuedToken");
    public static final TokenType SecureConversationToken = new TokenType("SecureConversationToken");
    public static final TokenType HttpsToken = new TokenType("HttpsToken");

    public static class TokenType extends XMLSecurityConstants.TokenType {
        protected TokenType(String name) {
            super(name);
        }
    }

    public enum KeyIdentifierType {
        DEFAULT_TOKEN,
        ISSUER_SERIAL,
        BST_DIRECT_REFERENCE,
        BST_EMBEDDED,
        X509_KEY_IDENTIFIER,
        SKI_KEY_IDENTIFIER,
        THUMBPRINT_IDENTIFIER,
        EMBEDDED_SECURITY_TOKEN_REF,
        EMEDDED_KEYIDENTIFIER_REF,
        USERNAMETOKEN_REFERENCE,
    }

    public enum DerivedKeyTokenReference {
        DirectReference,
        EncryptedKey,
        SecurityContextToken,
    }

    public enum UsernameTokenPasswordType {
        PASSWORD_NONE(null),
        PASSWORD_TEXT(NS_PASSWORD_TEXT),
        PASSWORD_DIGEST(NS_PASSWORD_DIGEST);

        private String namespace;
        private static final Map<String, UsernameTokenPasswordType> lookup = new HashMap<String, UsernameTokenPasswordType>();

        static {
            for (UsernameTokenPasswordType u : EnumSet.allOf(UsernameTokenPasswordType.class))
                lookup.put(u.getNamespace(), u);
        }

        UsernameTokenPasswordType(String namespace) {
            this.namespace = namespace;
        }

        public String getNamespace() {
            return namespace;
        }

        public static UsernameTokenPasswordType getUsernameTokenPasswordType(String namespace) {
            return lookup.get(namespace);
        }
    }


    /****************************************************************************
     * Fault codes defined in the WSS 1.1 spec under section 12, Error handling
     */

    /**
     * An unsupported token was provided
     */
    public static final QName UNSUPPORTED_SECURITY_TOKEN = new QName(NS_WSSE10, "UnsupportedSecurityToken");

    /**
     * An unsupported signature or encryption algorithm was used
     */
    public static final QName UNSUPPORTED_ALGORITHM = new QName(NS_WSSE10, "UnsupportedAlgorithm");

    /**
     * An error was discovered processing the <Security> header
     */
    public static final QName INVALID_SECURITY = new QName(NS_WSSE10, "InvalidSecurity");

    /**
     * An invalid security token was provided
     */
    public static final QName INVALID_SECURITY_TOKEN = new QName(NS_WSSE10, "InvalidSecurityToken");

    /**
     * The security token could not be authenticated or authorized
     */
    public static final QName FAILED_AUTHENTICATION = new QName(NS_WSSE10, "FailedAuthentication");

    /**
     * The signature or decryption was invalid
     */
    public static final QName FAILED_CHECK = new QName(NS_WSSE10, "FailedCheck");

    /**
     * Referenced security token could not be retrieved
     */
    public static final QName SECURITY_TOKEN_UNAVAILABLE = new QName(NS_WSSE10, "SecurityTokenUnavailable");

    /**
     * The message has expired
     */
    public static final QName MESSAGE_EXPIRED = new QName(NS_WSSE10, "MessageExpired");
}
