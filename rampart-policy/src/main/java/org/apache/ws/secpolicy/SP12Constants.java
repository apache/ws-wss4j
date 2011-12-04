package org.apache.ws.secpolicy;

import javax.xml.namespace.QName;

public class SP12Constants {

    public final static String SP_NS = "http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702";

    public final static String SP_PREFIX = "sp";
    
    public static final QName INCLUDE_TOKEN = new QName(SP_NS, SPConstants.ATTR_INCLUDE_TOKEN,
            SP12Constants.SP_PREFIX);
    
    public final static String INCLUDE_NEVER = SP12Constants.SP_NS + 
                                                                SPConstants.INCLUDE_TOKEN_NEVER_SUFFIX;

    public final static String INCLUDE_ONCE = SP12Constants.SP_NS + 
                                                                SPConstants.INCLUDE_TOKEN_ONCE_SUFFIX;

    public final static String INCLUDE_ALWAYS_TO_RECIPIENT = SP12Constants.SP_NS
        + SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT_SUFFIX;
    
    public final static String INCLUDE_ALWAYS_TO_INITIATOR = SP12Constants.SP_NS
    + SPConstants.INCLUDE_TOEKN_ALWAYS_TO_INITIATOR_SUFFIX;

    public final static String INCLUDE_ALWAYS = SP12Constants.SP_NS
        + SPConstants.INCLUDE_TOEKN_ALWAYS_SUFFIX;
    
    public static final QName TRUST_13 = new QName(SP12Constants.SP_NS, SPConstants.TRUST_13,
            SP12Constants.SP_PREFIX);
    
    public final static QName REQUIRE_CLIENT_CERTIFICATE = new QName(SP12Constants.SP_NS, "RequireClientCertificate", SP12Constants.SP_PREFIX); 
    
    public final static QName HTTP_BASIC_AUTHENTICATION = new QName(SP12Constants.SP_NS, "HttpBasicAuthentication", SP12Constants.SP_PREFIX);
    
    public final static QName HTTP_DIGEST_AUTHENTICATION = new QName(SP12Constants.SP_NS, "HttpDigestAuthentication", SP12Constants.SP_PREFIX);
    
    // /////////////////////////////////////////////////////////////////////

    public static final QName ATTR_XPATH_VERSION = new QName(SP_NS, SPConstants.XPATH_VERSION, SP12Constants.SP_PREFIX);
    
    ////////////////////////////////////////////////////////////////////////


    public static final QName TRANSPORT_BINDING = new QName(SP_NS,
            SPConstants.TRANSPORT_BINDING , SP12Constants.SP_PREFIX);

    public static final QName ALGORITHM_SUITE = new QName(SP_NS,
            SPConstants.ALGO_SUITE , SP12Constants.SP_PREFIX);

    public static final QName LAYOUT = new QName(SP_NS, SPConstants.LAYOUT, SP_PREFIX);


    public static final QName STRICT = new QName(SP12Constants.SP_NS, SPConstants.LAYOUT_STRICT,
            SP12Constants.SP_PREFIX);

    public static final QName LAX = new QName(SP12Constants.SP_NS, SPConstants.LAYOUT_LAX ,
            SP12Constants.SP_PREFIX);

    public static final QName LAXTSFIRST = new QName(SP12Constants.SP_NS,
            SPConstants.LAYOUT_LAX_TIMESTAMP_FIRST, SP12Constants.SP_PREFIX);

    public static final QName LAXTSLAST = new QName(SP12Constants.SP_NS,
            SPConstants.LAYOUT_LAX_TIMESTAMP_LAST, SP12Constants.SP_PREFIX);

    // ////////////////

    public static final QName INCLUDE_TIMESTAMP = new QName(SP12Constants.SP_NS,
            SPConstants.INCLUDE_TIMESTAMP, SP12Constants.SP_PREFIX);
    
    public static final QName ENCRYPT_BEFORE_SIGNING = new QName(SP12Constants.SP_NS, 
            SPConstants.ENCRYPT_BEFORE_SIGNING, SP12Constants.SP_PREFIX);
    
    public static final QName SIGN_BEFORE_ENCRYPTING = new QName(SP12Constants.SP_NS,
            SPConstants.SIGN_BEFORE_ENCRYPTING, SP12Constants.SP_PREFIX);
    
    public static final QName ONLY_SIGN_ENTIRE_HEADERS_AND_BODY = new QName(SP12Constants.SP_NS,
            SPConstants.ONLY_SIGN_ENTIRE_HEADERS_AND_BODY,SP12Constants.SP_PREFIX);

    public static final QName TRANSPORT_TOKEN = new QName(SP_NS,
            SPConstants.TRANSPORT_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName HTTPS_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.HTTPS_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName SECURITY_CONTEXT_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SECURITY_CONTEXT_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName SECURE_CONVERSATION_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SECURE_CONVERSATION_TOKEN , SP12Constants.SP_PREFIX);

    public static final QName SIGNATURE_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.SIGNATURE_TOKEN , SP12Constants.SP_PREFIX);

    public static final QName SIGNED_PARTS = new QName(SP12Constants.SP_NS,
            SPConstants.SIGNED_PARTS , SP12Constants.SP_PREFIX);
    
    public static final QName ENCRYPTED_PARTS = new QName(SP12Constants.SP_NS,
            SPConstants.ENCRYPTED_PARTS , SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ELEMENTS = new QName(SP12Constants.SP_NS,
            SPConstants.SIGNED_ELEMENTS , SP12Constants.SP_PREFIX);

    public static final QName ENCRYPTED_ELEMENTS = new QName(SP12Constants.SP_NS,
            SPConstants.ENCRYPTED_ELEMENTS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRED_ELEMENTS = new QName(SP12Constants.SP_NS,
            SPConstants.REQUIRED_ELEMENTS, SP12Constants.SP_PREFIX);
    
    public static final QName REQUIRED_PARTS = new QName(SP12Constants.SP_NS,
            SPConstants.REQUIRED_PARTS, SP12Constants.SP_PREFIX);
    
    public static final QName CONTENT_ENCRYPTED_ELEMENTS = new QName(SP12Constants.SP_NS,
            SPConstants.CONTENT_ENCRYPTED_ELEMENTS, SP12Constants.SP_PREFIX);

    public static final QName USERNAME_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.USERNAME_TOKEN , SP12Constants.SP_PREFIX);

    public static final QName WSS_USERNAME_TOKEN10 = new QName(SP12Constants.SP_NS,
            SPConstants.USERNAME_TOKEN10 , SP12Constants.SP_PREFIX);

    public static final QName WSS_USERNAME_TOKEN11 = new QName(SP12Constants.SP_NS,
            SPConstants.USERNAME_TOKEN11 , SP12Constants.SP_PREFIX);

    public static final QName ENCRYPTION_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.ENCRYPTION_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName X509_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.X509_TOKEN , SP12Constants.SP_PREFIX);
    
    public static final QName WSS_X509_V1_TOKEN_10 = new QName(SP12Constants.SP_NS,
            SPConstants.WSS_X509_V1_TOKEN10 , SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_V3_TOKEN_10 = new QName(SP12Constants.SP_NS,
            SPConstants.WSS_X509_V3_TOKEN10 , SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKCS7_TOKEN_10 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKCS7_TOKEN10 , SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKI_PATH_V1_TOKEN_10 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKI_PATH_V1_TOKEN10 , SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_V1_TOKEN_11 = new QName(SP12Constants.SP_NS,
            SPConstants.WSS_X509_V1_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_V3_TOKEN_11 = new QName(SP12Constants.SP_NS,
            SPConstants.WSS_X509_V3_TOKEN11 , SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKCS7_TOKEN_11 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKCS7_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName WSS_X509_PKI_PATH_V1_TOKEN_11 = new QName(
            SP12Constants.SP_NS, SPConstants.WSS_X509_PKI_PATH_V1_TOKEN11, SP12Constants.SP_PREFIX);

    public static final QName ISSUED_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.ISSUED_TOKEN , SP12Constants.SP_PREFIX);

    public static final QName SUPPORTING_TOKENS = new QName(SP12Constants.SP_NS,
            SPConstants.SUPPORTING_TOKENS , SP12Constants.SP_PREFIX);

    public static final QName SIGNED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_SUPPORTING_TOKENS , SP12Constants.SP_PREFIX);

    public static final QName ENDORSING_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.ENDORSING_SUPPORTING_TOKENS , SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ENDORSING_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_ENDORSING_SUPPORTING_TOKENS,
            SP12Constants.SP_PREFIX);
    
    public static final QName ENCRYPTED_SUPPORTING_TOKENS = new QName(SP12Constants.SP_NS,
            SPConstants.ENCRYPTED_SUPPORTING_TOKENS , SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ENCRYPTED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_ENCRYPTED_SUPPORTING_TOKENS , SP12Constants.SP_PREFIX);

    public static final QName ENDORSING_ENCRYPTED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.ENDORSING_ENCRYPTED_SUPPORTING_TOKENS , SP12Constants.SP_PREFIX);

    public static final QName SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS,
            SP12Constants.SP_PREFIX);

    public static final QName PROTECTION_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.PROTECTION_TOKEN, SP12Constants.SP_PREFIX);

    public static final QName ASYMMETRIC_BINDING = new QName(SP12Constants.SP_NS,
            SPConstants.ASYMMETRIC_BINDING, SP12Constants.SP_PREFIX);
    
    public static final QName SYMMETRIC_BINDING = new QName(SP12Constants.SP_NS,
            SPConstants.SYMMETRIC_BINDING, SP12Constants.SP_PREFIX);

    public static final QName INITIATOR_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.INITIATOR_TOKEN , SP12Constants.SP_PREFIX);

    public static final QName RECIPIENT_TOKEN = new QName(SP12Constants.SP_NS,
            SPConstants.RECIPIENT_TOKEN , SP12Constants.SP_PREFIX);

    public static final QName ENCRYPT_SIGNATURE = new QName(SP12Constants.SP_NS,
            SPConstants.ENCRYPT_SIGNATURE , SP12Constants.SP_PREFIX);

    public static final QName PROTECT_TOKENS = new QName(SP12Constants.SP_NS,
            SPConstants.PROTECT_TOKENS, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_KEY_IDENTIFIRE_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_KEY_IDENTIFIRE_REFERENCE ,
            SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_ISSUER_SERIAL_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_ISSUER_SERIAL_REFERENCE,
            SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_EMBEDDED_TOKEN_REFERENCE = new QName(
            SP12Constants.SP_NS,SPConstants.REQUIRE_EMBEDDED_TOKEN_REFERENCE,
            SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_THUMBPRINT_REFERENCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_THUMBPRINT_REFERENCE , SP12Constants.SP_PREFIX);


    public static final QName MUST_SUPPORT_REF_KEY_IDENTIFIER = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_KEY_IDENTIFIER , SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_ISSUER_SERIAL = new QName(
            SP12Constants.SP_NS,SPConstants.MUST_SUPPORT_REF_ISSUER_SERIAL, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_EXTERNAL_URI = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_EXTERNAL_URI , SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_EMBEDDED_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_EMBEDDED_TOKEN, SP12Constants.SP_PREFIX);
    
    public static final QName MUST_SUPPORT_REF_THUMBPRINT = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_THUMBPRINT, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_ENCRYPTED_KEY = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_ENCRYPTED_KEY, SP12Constants.SP_PREFIX);

    public static final QName WSS10 = new QName(SP12Constants.SP_NS, SPConstants.WSS10 ,
            SP12Constants.SP_PREFIX);

    public static final QName WSS11 = new QName(SP12Constants.SP_NS, SPConstants.WSS11,
            SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_SIGNATURE_CONFIRMATION = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_SIGNATURE_CONFIRMATION ,
            SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_CLIENT_CHALLENGE = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_CLIENT_CHALLENGE, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_SERVER_CHALLENGE = new QName(
            SP12Constants.SP_NS,SPConstants.MUST_SUPPORT_SERVER_CHALLENGE , SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_CLIENT_ENTROPY = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_CLIENT_ENTROPY, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_SERVER_ENTROPY = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_SERVER_ENTROPY, SP12Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_ISSUED_TOKENS = new QName(
            SP12Constants.SP_NS, SPConstants.MUST_SUPPORT_ISSUED_TOKENS , SP12Constants.SP_PREFIX);
    
    public static final QName REQUIRE_REQUEST_SECURITY_TOKEN_COLLECTION = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_REQUEST_SECURITY_TOKEN_COLLECTION , SP12Constants.SP_PREFIX);
    
    public static final QName REQUIRE_APPLIES_TO = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_APPLIES_TO, SP12Constants.SP_PREFIX);

    public static final QName ISSUER = new QName(SP12Constants.SP_NS, SPConstants.ISSUER ,
            SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_DERIVED_KEYS = new QName(SP12Constants.SP_NS,
            SPConstants.REQUIRE_DERIVED_KEYS, SP12Constants.SP_PREFIX);
    
    public static final QName REQUIRE_IMPLIED_DERIVED_KEYS = new QName(SP12Constants.SP_NS,
            SPConstants.REQUIRE_IMPLIED_DERIVED_KEYS, SP12Constants.SP_PREFIX);
    
    public static final QName REQUIRE_EXPLICIT_DERIVED_KEYS = new QName(SP12Constants.SP_NS,
            SPConstants.REQUIRE_EXPLICIT_DERIVED_KEYS, SP12Constants.SP_PREFIX);
    
    public static final QName REQUIRE_EXTERNAL_URI_REFERNCE = new QName(
            SP12Constants.SP_NS,SPConstants.REQUIRE_EXTERNAL_URI_REFERNCE, SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_EXTERNAL_REFERNCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_EXTERNAL_REFERNCE , SP12Constants.SP_PREFIX);

    public static final QName REQUIRE_INTERNAL_REFERNCE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUIRE_INTERNAL_REFERNCE , SP12Constants.SP_PREFIX);

    public static final QName REQUEST_SECURITY_TOKEN_TEMPLATE = new QName(
            SP12Constants.SP_NS, SPConstants.REQUEST_SECURITY_TOKEN_TEMPLATE,
            SP12Constants.SP_PREFIX);

    public static final QName SC10_SECURITY_CONTEXT_TOKEN = new QName(
            SP12Constants.SP_NS, SPConstants.SC10_SECURITY_CONTEXT_TOKEN , SP12Constants.SP_PREFIX);

    public static final QName BOOTSTRAP_POLICY = new QName(SP12Constants.SP_NS,
            SPConstants.BOOTSTRAP_POLICY , SP12Constants.SP_PREFIX);

    public final static QName XPATH = new QName(SP12Constants.SP_NS, SPConstants.XPATH_EXPR,
            SP12Constants.SP_PREFIX);
    
    public static final QName NO_PASSWORD = new QName(SP12Constants.SP_NS, SPConstants.NO_PASSWORD,
            SP12Constants.SP_PREFIX);
    
    public static final QName HASH_PASSWORD = new QName(SP12Constants.SP_NS, SPConstants.HASH_PASSWORD,
            SP12Constants.SP_PREFIX);

    // /////////////////////////////////////////////////////////////////////////////////////////////
    
    public static final QName HEADER = new QName(SP12Constants.SP_NS, SPConstants.HEADER);
    
    public static final QName BODY = new QName(SP12Constants.SP_NS, SPConstants.BODY);
    
    public static final QName ATTACHMENTS = new QName(SP12Constants.SP_NS, SPConstants.ATTACHMENTS);
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    
    public static int getInclusionFromAttributeValue(String value ) {
        
        if (INCLUDE_ALWAYS.equals(value)) {
            return SPConstants.INCLUDE_TOEKN_ALWAYS;
        } else if (INCLUDE_ALWAYS_TO_RECIPIENT.equals(value)) {
            return SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT;
        } else if (INCLUDE_ALWAYS_TO_INITIATOR.equals(value)) { 
            return SPConstants.INCLUDE_TOEKN_ALWAYS_TO_INITIATOR;
        } else if (INCLUDE_NEVER.equals(value)) {
            return SPConstants.INCLUDE_TOKEN_NEVER;
        } else if (INCLUDE_ONCE.equals(value)) {
            return SPConstants.INCLUDE_TOKEN_ONCE;
        } else {
            return -1;
        }   
    }
    
    public static String getAttributeValueFromInclusion(int value) {
        
        switch(value) {
            case SPConstants.INCLUDE_TOEKN_ALWAYS:
                return SP12Constants.INCLUDE_ALWAYS;
            case SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT:
                return SP12Constants.INCLUDE_ALWAYS_TO_RECIPIENT;
            case SPConstants.INCLUDE_TOEKN_ALWAYS_TO_INITIATOR:
                return SP12Constants.INCLUDE_ALWAYS_TO_INITIATOR;
            case SPConstants.INCLUDE_TOKEN_NEVER:
                return SP12Constants.INCLUDE_NEVER;
            case SPConstants.INCLUDE_TOKEN_ONCE:
                return SP12Constants.INCLUDE_ONCE;
            default :
                return null;
        }
        
    }

}
