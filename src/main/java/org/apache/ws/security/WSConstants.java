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

package org.apache.ws.security;

import javax.xml.namespace.QName;

/**
 * Constants in WS-Security spec.
 */
public final class WSConstants {
    
    /*
     * Standard constants used in WSS4J
     */
    
    //
    // Namespaces
    //
    public static final String WSSE_NS = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String WSSE11_NS = 
        "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
    public static final String WSU_NS = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    
    public static final String SOAPMESSAGE_NS = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";
    public static final String SOAPMESSAGE_NS11 = 
        "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1";
    public static final String USERNAMETOKEN_NS = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0";
    public static final String X509TOKEN_NS = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";
    public static final String SAMLTOKEN_NS = 
        "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0";
    public static final String SAMLTOKEN_NS11 = 
        "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1";
    public static final String KERBEROS_NS11 =
        "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1"; 

    public static final String SIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String ENC_NS = "http://www.w3.org/2001/04/xmlenc#";
    public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    public static final String XML_NS = "http://www.w3.org/XML/1998/namespace";
    
    public static final String SAML_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
    public static final String SAMLP_NS = "urn:oasis:names:tc:SAML:1.0:protocol";
    public static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String SAMLP2_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    
    public static final String URI_SOAP11_ENV =
        "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String URI_SOAP12_ENV =
        "http://www.w3.org/2003/05/soap-envelope";
    public static final String URI_SOAP11_NEXT_ACTOR =
        "http://schemas.xmlsoap.org/soap/actor/next";
    public static final String URI_SOAP12_NEXT_ROLE =
        "http://www.w3.org/2003/05/soap-envelope/role/next";
    public static final String URI_SOAP12_NONE_ROLE =
        "http://www.w3.org/2003/05/soap-envelope/role/none";
    public static final String URI_SOAP12_ULTIMATE_ROLE =
        "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver";
    
    public static final String C14N_OMIT_COMMENTS = 
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public static final String C14N_WITH_COMMENTS = 
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    public static final String C14N_EXCL_OMIT_COMMENTS = 
        "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String C14N_EXCL_WITH_COMMENTS = 
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    
    public static final String NS_XMLDSIG_FILTER2 = 
        "http://www.w3.org/2002/06/xmldsig-filter2";
    public static final String NS_XMLDSIG_ENVELOPED_SIGNATURE = 
        SIG_NS + "enveloped-signature";
    public static final String SWA_ATTACHMENT_CONTENT_SIG_TRANS = 
        "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";
    public static final String SWA_ATTACHMENT_COMPLETE_SIG_TRANS = 
        "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform";
    
    public static final String KEYTRANSPORT_RSA15 = 
        "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    public static final String KEYTRANSPORT_RSAOEP = 
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    public static final String TRIPLE_DES = 
        "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
    public static final String AES_128 = 
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    public static final String AES_256 = 
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    public static final String AES_192 = 
        "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
    public static final String AES_128_GCM = 
        "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    public static final String AES_192_GCM = 
        "http://www.w3.org/2009/xmlenc11#aes192-gcm";
    public static final String AES_256_GCM = 
        "http://www.w3.org/2009/xmlenc11#aes256-gcm";
    public static final String DSA = 
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
    public static final String RSA = 
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    public static final String RSA_SHA1 = 
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    public static final String SHA1 = 
        "http://www.w3.org/2000/09/xmldsig#sha1";
    public static final String SHA256 =
        "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String HMAC_SHA1 = 
        "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    public static final String HMAC_SHA256 = 
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
    public static final String HMAC_SHA384 = 
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
    public static final String HMAC_SHA512 = 
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
    public static final String HMAC_MD5 = 
        "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";
    
    public static final String WST_NS = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    /**
     * WS-Trust 1.3 namespace
     */
    public static final String WST_NS_05_12 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    /**
     * WS-Trust 1.4 namespace
     */
    public static final String WST_NS_08_02 = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
    
    public static final String WSC_SCT = "http://schemas.xmlsoap.org/ws/2005/02/sc/sct";
    
    public static final String WSC_SCT_05_12 = 
        "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct";

    //
    // Localnames
    //
    public static final String WSSE_LN = "Security";
    public static final String THUMBPRINT ="ThumbprintSHA1";
    public static final String SAML_ASSERTION_ID = "SAMLAssertionID";
    public static final String SAML2_ASSERTION_ID = "SAMLID";
    public static final String ENC_KEY_VALUE_TYPE = "EncryptedKey";
    public static final String ENC_KEY_SHA1_URI = "EncryptedKeySHA1";
    public static final String SIG_LN = "Signature";
    public static final String SIG_INFO_LN = "SignedInfo";
    public static final String ENC_KEY_LN = "EncryptedKey";
    public static final String ENC_DATA_LN = "EncryptedData";
    public static final String REF_LIST_LN = "ReferenceList";
    public static final String REF_LN = "Reference";
    public static final String USERNAME_TOKEN_LN = "UsernameToken";
    public static final String BINARY_TOKEN_LN = "BinarySecurityToken";
    public static final String TIMESTAMP_TOKEN_LN = "Timestamp";
    public static final String USERNAME_LN = "Username";
    public static final String PASSWORD_LN = "Password";
    public static final String PASSWORD_TYPE_ATTR = "Type";
    public static final String NONCE_LN = "Nonce";
    public static final String CREATED_LN = "Created";
    public static final String EXPIRES_LN = "Expires";
    public static final String SIGNATURE_CONFIRMATION_LN = "SignatureConfirmation"; 
    public static final String SALT_LN = "Salt";
    public static final String ITERATION_LN = "Iteration";
    public static final String ASSERTION_LN = "Assertion";
    public static final String PW_DIGEST = "PasswordDigest";
    public static final String PW_TEXT = "PasswordText";
    public static final String PW_NONE = "PasswordNone";
    public static final String ENCRYPTED_HEADER = "EncryptedHeader";
    public static final String X509_ISSUER_SERIAL_LN = "X509IssuerSerial";
    public static final String X509_ISSUER_NAME_LN = "X509IssuerName";
    public static final String X509_SERIAL_NUMBER_LN = "X509SerialNumber";
    public static final String X509_DATA_LN = "X509Data";
    public static final String X509_CERT_LN = "X509Certificate";
    public static final String KEYINFO_LN = "KeyInfo";
    public static final String KEYVALUE_LN = "KeyValue";
    public static final String TOKEN_TYPE = "TokenType";
    
    public static final String ELEM_ENVELOPE = "Envelope";
    public static final String ELEM_HEADER = "Header";
    public static final String ELEM_BODY = "Body";
    public static final String ATTR_MUST_UNDERSTAND = "mustUnderstand";
    public static final String ATTR_ACTOR = "actor";
    public static final String ATTR_ROLE = "role";
    public static final String NULL_NS = "Null";
    
    //
    // Prefixes
    //
    public static final String WSSE_PREFIX = "wsse";
    public static final String WSSE11_PREFIX = "wsse11";
    public static final String WSU_PREFIX = "wsu";
    public static final String DEFAULT_SOAP_PREFIX = "soapenv";
    public static final String SIG_PREFIX = "ds";
    public static final String ENC_PREFIX = "xenc";
    public static final String C14N_EXCL_OMIT_COMMENTS_PREFIX = "ec";
    
    
    //
    // Fault codes defined in the WSS 1.1 spec under section 12, Error handling
    //
    
    /**
     * An unsupported token was provided
     */
    public static final QName UNSUPPORTED_SECURITY_TOKEN = 
        new QName(WSSE_NS, "UnsupportedSecurityToken");
    
    /**
     * An unsupported signature or encryption algorithm was used
     */
    public static final QName UNSUPPORTED_ALGORITHM  = 
        new QName(WSSE_NS, "UnsupportedAlgorithm");
    
    /**
     * An error was discovered processing the <Security> header
     */
    public static final QName INVALID_SECURITY = 
        new QName (WSSE_NS, "InvalidSecurity");
    
    /**
     * An invalid security token was provided
     */
    public static final QName INVALID_SECURITY_TOKEN = 
        new QName (WSSE_NS, "InvalidSecurityToken");
    
    /**
     * The security token could not be authenticated or authorized
     */
    public static final QName FAILED_AUTHENTICATION = 
        new QName (WSSE_NS, "FailedAuthentication");
    
    /**
     * The signature or decryption was invalid
     */
    public static final QName FAILED_CHECK = 
        new QName (WSSE_NS, "FailedCheck");
    
    /** 
     * Referenced security token could not be retrieved
     */
    public static final QName SECURITY_TOKEN_UNAVAILABLE = 
        new QName (WSSE_NS, "SecurityTokenUnavailable");
    
    /** 
     * The message has expired
     */
    public static final QName MESSAGE_EXPIRED = 
        new QName (WSSE_NS, "MessageExpired");

    //
    // Kerberos ValueTypes
    //
    public static final String WSS_KRB_V5_AP_REQ = KERBEROS_NS11 + "#Kerberosv5_AP_REQ";
    public static final String WSS_GSS_KRB_V5_AP_REQ = KERBEROS_NS11 + "#GSS_Kerberosv5_AP_REQ";
    public static final String WSS_KRB_V5_AP_REQ1510 = KERBEROS_NS11 + "#Kerberosv5_AP_REQ1510";
    public static final String WSS_GSS_KRB_V5_AP_REQ1510 = 
        KERBEROS_NS11 + "#GSS_Kerberosv5_AP_REQ1510";
    public static final String WSS_KRB_V5_AP_REQ4120 = KERBEROS_NS11 + "#Kerberosv5_AP_REQ4120";
    public static final String WSS_GSS_KRB_V5_AP_REQ4120 = 
        KERBEROS_NS11 + "#GSS_Kerberosv5_AP_REQ4120";
    public static final String WSS_KRB_KI_VALUE_TYPE = KERBEROS_NS11 + "#Kerberosv5APREQSHA1";
    
    //
    // Misc
    //
    public static final String WSS_SAML_KI_VALUE_TYPE = SAMLTOKEN_NS + "#" + SAML_ASSERTION_ID;
    public static final String WSS_SAML2_KI_VALUE_TYPE = SAMLTOKEN_NS11 + "#" + SAML2_ASSERTION_ID;
    public static final String WSS_SAML_TOKEN_TYPE = SAMLTOKEN_NS11 + "#SAMLV1.1";
    public static final String WSS_SAML2_TOKEN_TYPE = SAMLTOKEN_NS11 + "#SAMLV2.0";
    public static final String WSS_ENC_KEY_VALUE_TYPE = SOAPMESSAGE_NS11 + "#" + ENC_KEY_VALUE_TYPE;
    public static final String PASSWORD_DIGEST = USERNAMETOKEN_NS + "#PasswordDigest";
    public static final String PASSWORD_TEXT = USERNAMETOKEN_NS + "#PasswordText";
    public static final String WSS_USERNAME_TOKEN_VALUE_TYPE = 
        USERNAMETOKEN_NS + "#" + USERNAME_TOKEN_LN;

    public static final String[] URIS_SOAP_ENV = {
        URI_SOAP11_ENV,
        URI_SOAP12_ENV,
    };

    /*
     * Constants used to configure WSS4J
     */

    /**
     * Sets the {@link 
     * org.apache.ws.security.message.WSSecSignature#build(Document, Crypto, WSSecHeader) 
     * } method to send the signing certificate as a <code>BinarySecurityToken</code>.
     * <p/>
     * The signing method takes the signing certificate, converts it to a
     * <code>BinarySecurityToken</code>, puts it in the security header,
     * and inserts a <code>Reference</code> to the binary security token
     * into the <code>wsse:SecurityReferenceToken</code>. Thus the whole
     * signing certificate is transfered to the receiver.
     * The X509 profile recommends to use {@link #ISSUER_SERIAL} instead
     * of sending the whole certificate.
     * <p/>
     * Please refer to WS Security specification X509 1.1 profile, chapter 3.3.2
     * and to WS Security SOAP Message security 1.1 specification, chapter 7.2
     * <p/>
     * Note: only local references to BinarySecurityToken are supported
     */
    public static final int BST_DIRECT_REFERENCE = 1;

    /**
     * Sets the {@link 
     * org.apache.ws.security.message.WSSecSignature#build(Document, Crypto, WSSecHeader)
     * } or the {@link 
     * org.apache.ws.security.message.WSSecEncrypt#build(Document, Crypto, WSSecHeader)
     * } method to send the issuer name and the serial number of a certificate to
     * the receiver.
     * <p/>
     * In contrast to {@link #BST_DIRECT_REFERENCE} only the issuer name
     * and the serial number of the signing certificate are sent to the
     * receiver. This reduces the amount of data being sent. The encryption
     * method uses the public key associated with this certificate to encrypt
     * the symmetric key used to encrypt data.
     * <p/>
     * Please refer to WS Security specification X509 1.1 profile, chapter 3.3.3
     */
    public static final int ISSUER_SERIAL = 2;

    /**
     * Sets the {@link 
     * org.apache.ws.security.message.WSSecSignature#build(Document, Crypto, WSSecHeader)
     * } or the {@link 
     * org.apache.ws.security.message.WSSecEncrypt#build(Document, Crypto, WSSecHeader)
     * }method to send the certificate used to encrypt the symmetric key.
     * <p/>
     * The encryption method uses the public key associated with this certificate
     * to encrypt the symmetric key used to encrypt data. The certificate is
     * converted into a <code>KeyIdentifier</code> token and sent to the receiver.
     * Thus the complete certificate data is transfered to receiver.
     * The X509 profile recommends to use {@link #ISSUER_SERIAL} instead
     * of sending the whole certificate.
     * <p/>
     * Please refer to WS Security SOAP Message security 1.1 specification, 
     * chapter 7.3. Note that this is a NON-STANDARD method. The standard way to refer to
     * an X.509 Certificate via a KeyIdentifier is to use {@link #SKI_KEY_IDENTIFIER}
     */
    public static final int X509_KEY_IDENTIFIER = 3;
    
    /**
     * Sets the {@link 
     * org.apache.ws.security.message.WSSecSignature#build(Document, Crypto, WSSecHeader)
     * } method to send a <code>SubjectKeyIdentifier</code> to identify
     * the signing certificate.
     * <p/>
     * Refer to WS Security specification X509 1.1 profile, chapter 3.3.1
     */
    public static final int SKI_KEY_IDENTIFIER = 4;

    /**
     * Embeds a keyinfo/key name into the EncryptedData element.
     * <p/>
     */
    public static final int EMBEDDED_KEYNAME = 5;
    
    /**
     * Embeds a keyinfo/wsse:SecurityTokenReference into EncryptedData element.
     */
    public static final int EMBED_SECURITY_TOKEN_REF = 6;
    
    /**
     * <code>UT_SIGNING</code> is used internally only to set a specific Signature
     * behavior.
     * 
     * The signing token is constructed from values in the UsernameToken according
     * to WS-Trust specification.
     */
    public static final int UT_SIGNING = 7;
    
    /**
     * <code>THUMPRINT_IDENTIFIER</code> is used to set the specific key identifier
     * ThumbprintSHA1.
     * 
     * This identifier uses the SHA-1 digest of a security token to
     * identify the security token. Please refer to chapter 7.2 of the OASIS WSS 1.1
     * specification.
     * 
     */
    public static final int THUMBPRINT_IDENTIFIER = 8;
    
    /**
     * <code>CUSTOM_SYMM_SIGNING</code> is used internally only to set a 
     * specific Signature behavior.
     * 
     * The signing key, reference id and value type are set externally. 
     */
    public static final int CUSTOM_SYMM_SIGNING = 9;
    
    /**
     * <code>ENCRYPTED_KEY_SHA1_IDENTIFIER</code> is used to set the specific key identifier
     * EncryptedKeySHA1.
     * 
     * This identifier uses the SHA-1 digest of a security token to
     * identify the security token. Please refer to chapter 7.3 of the OASIS WSS 1.1
     * specification.
     */
    public static final int ENCRYPTED_KEY_SHA1_IDENTIFIER = 10;
    
    /**
     * <code>CUSTOM_SYMM_SIGNING_DIRECT</code> is used internally only to set a 
     * specific Signature behavior.
     * 
     * The signing key, reference id and value type are set externally. 
     */
    public static final int CUSTOM_SYMM_SIGNING_DIRECT = 11;
    
    /**
     * <code>CUSTOM_KEY_IDENTIFIER</code> is used to set a KeyIdentifier to
     * a particular ID
     * 
     * The reference id and value type are set externally. 
     */
    public static final int CUSTOM_KEY_IDENTIFIER = 12;
    
    /**
     * <code>KEY_VALUE</code> is used to set a ds:KeyInfo/ds:KeyValue element to refer to
     * either an RSA or DSA public key.
     */
    public static final int KEY_VALUE = 13;
    
    /*
     * The following values are bits that can be combined to for a set.
     * Be careful when selecting new values.
     */
    public static final int NO_SECURITY = 0;
    public static final int UT = 0x1; // perform UsernameToken
    public static final int SIGN = 0x2; // Perform Signature
    public static final int ENCR = 0x4; // Perform Encryption

    public static final int ST_UNSIGNED = 0x8; // perform SAMLToken unsigned
    public static final int ST_SIGNED = 0x10; // perform SAMLToken signed

    public static final int TS = 0x20; // insert Timestamp
    public static final int UT_SIGN = 0x40; // perform signature with UT secret key
    public static final int SC = 0x80;      // this is a SignatureConfirmation

    public static final int NO_SERIALIZE = 0x100;
    public static final int SERIALIZE = 0x200;
    public static final int SCT = 0x400; //SecurityContextToken
    public static final int DKT = 0x800; //DerivedKeyToken
    public static final int BST = 0x1000; //BinarySecurityToken
    public static final int UT_NOPASSWORD = 0x2000; // perform UsernameToken

    /**
     * Length of UsernameToken derived key used by .NET WSE to sign a message.
     */
    public static final int WSE_DERIVED_KEY_LEN = 16;
    public static final String LABEL_FOR_DERIVED_KEY = "WS-Security";
    
    private WSConstants() {
        // Complete
    }
    
}
