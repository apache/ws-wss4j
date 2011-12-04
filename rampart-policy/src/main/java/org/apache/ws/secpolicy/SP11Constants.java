package org.apache.ws.secpolicy;

import javax.xml.namespace.QName;

public class SP11Constants {
    
    public final static String SP_NS = "http://schemas.xmlsoap.org/ws/2005/07/securitypolicy";

    public final static String SP_PREFIX = "sp";
    
    
    public static final QName INCLUDE_TOKEN = new QName(SP_NS, SPConstants.ATTR_INCLUDE_TOKEN,
            SP11Constants.SP_PREFIX);
    
    public final static String INCLUDE_NEVER = SP11Constants.SP_NS + 
                                                                SPConstants.INCLUDE_TOKEN_NEVER_SUFFIX;

    public final static String INCLUDE_ONCE = SP11Constants.SP_NS + 
                                                                SPConstants.INCLUDE_TOKEN_ONCE_SUFFIX;

    public final static String INCLUDE_ALWAYS_TO_RECIPIENT = SP11Constants.SP_NS
        + SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT_SUFFIX;

    public final static String INCLUDE_ALWAYS = SP11Constants.SP_NS
        + SPConstants.INCLUDE_TOEKN_ALWAYS_SUFFIX;
    
    // /////////////////////////////////////////////////////////////////////

    public static final QName ATTR_XPATH_VERSION = new QName(SP_NS, SPConstants.XPATH_VERSION, SP11Constants.SP_PREFIX);
    
    ////////////////////////////////////////////////////////////////////////


    public static final QName TRANSPORT_BINDING = new QName(SP_NS,
            SPConstants.TRANSPORT_BINDING , SP11Constants.SP_PREFIX);

    public static final QName ALGORITHM_SUITE = new QName(SP_NS,
            SPConstants.ALGO_SUITE , SP11Constants.SP_PREFIX);

    public static final QName LAYOUT = new QName(SP_NS, SPConstants.LAYOUT, SP_PREFIX);


    public static final QName STRICT = new QName(SP11Constants.SP_NS, SPConstants.LAYOUT_STRICT,
            SP11Constants.SP_PREFIX);

    public static final QName LAX = new QName(SP11Constants.SP_NS, SPConstants.LAYOUT_LAX ,
            SP11Constants.SP_PREFIX);

    public static final QName LAXTSFIRST = new QName(SP11Constants.SP_NS,
            SPConstants.LAYOUT_LAX_TIMESTAMP_FIRST, SP11Constants.SP_PREFIX);

    public static final QName LAXTSLAST = new QName(SP11Constants.SP_NS,
            SPConstants.LAYOUT_LAX_TIMESTAMP_LAST, SP11Constants.SP_PREFIX);

    // ////////////////

    public static final QName INCLUDE_TIMESTAMP = new QName(SP_NS,
            SPConstants.INCLUDE_TIMESTAMP, SP11Constants.SP_PREFIX);

    public static final QName TRANSPORT_TOKEN = new QName(SP_NS,
            SPConstants.TRANSPORT_TOKEN, SP11Constants.SP_PREFIX);

    public static final QName HTTPS_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.HTTPS_TOKEN, SP11Constants.SP_PREFIX);

    public static final QName SECURITY_CONTEXT_TOKEN = new QName(
            SP11Constants.SP_NS, SPConstants.SECURITY_CONTEXT_TOKEN, SP11Constants.SP_PREFIX);

    public static final QName SECURE_CONVERSATION_TOKEN = new QName(
            SP11Constants.SP_NS, SPConstants.SECURE_CONVERSATION_TOKEN , SP11Constants.SP_PREFIX);

    public static final QName SIGNATURE_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.SIGNATURE_TOKEN , SP11Constants.SP_PREFIX);

    public static final QName SIGNED_PARTS = new QName(SP11Constants.SP_NS,
            SPConstants.SIGNED_PARTS , SP11Constants.SP_PREFIX);
    
    public static final QName ENCRYPTED_PARTS = new QName(SP11Constants.SP_NS,
            SPConstants.ENCRYPTED_PARTS , SP11Constants.SP_PREFIX);

    public static final QName SIGNED_ELEMENTS = new QName(SP11Constants.SP_NS,
            SPConstants.SIGNED_ELEMENTS , SP11Constants.SP_PREFIX);

    public static final QName ENCRYPTED_ELEMENTS = new QName(SP11Constants.SP_NS,
            SPConstants.ENCRYPTED_ELEMENTS, SP11Constants.SP_PREFIX);
    
    public static final QName REQUIRED_ELEMENTS = new QName(SP11Constants.SP_NS,
            SPConstants.REQUIRED_ELEMENTS, SP11Constants.SP_PREFIX);

    public static final QName USERNAME_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.USERNAME_TOKEN , SP11Constants.SP_PREFIX);

    public static final QName WSS_USERNAME_TOKEN10 = new QName(SP11Constants.SP_NS,
            SPConstants.USERNAME_TOKEN10 , SP11Constants.SP_PREFIX);

    public static final QName WSS_USERNAME_TOKEN11 = new QName(SP11Constants.SP_NS,
            SPConstants.USERNAME_TOKEN11 , SP11Constants.SP_PREFIX);

    public static final QName ENCRYPTION_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.ENCRYPTION_TOKEN, SP11Constants.SP_PREFIX);

    public static final QName X509_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.X509_TOKEN , SP11Constants.SP_PREFIX);
    
    public static final QName WSS_X509_V1_TOKEN_10 = new QName(SP11Constants.SP_NS,
            SPConstants.WSS_X509_V1_TOKEN10 , SP11Constants.SP_PREFIX);

    public static final QName WSS_X509_V3_TOKEN_10 = new QName(SP11Constants.SP_NS,
            SPConstants.WSS_X509_V3_TOKEN10 , SP11Constants.SP_PREFIX);

    public static final QName WSS_X509_PKCS7_TOKEN_10 = new QName(
            SP11Constants.SP_NS, SPConstants.WSS_X509_PKCS7_TOKEN10 , SP11Constants.SP_PREFIX);

    public static final QName WSS_X509_PKI_PATH_V1_TOKEN_10 = new QName(
            SP11Constants.SP_NS, SPConstants.WSS_X509_PKI_PATH_V1_TOKEN10 , SP11Constants.SP_PREFIX);

    public static final QName WSS_X509_V1_TOKEN_11 = new QName(SP11Constants.SP_NS,
            SPConstants.WSS_X509_V1_TOKEN11, SP11Constants.SP_PREFIX);

    public static final QName WSS_X509_V3_TOKEN_11 = new QName(SP11Constants.SP_NS,
            SPConstants.WSS_X509_V3_TOKEN11 , SP11Constants.SP_PREFIX);

    public static final QName WSS_X509_PKCS7_TOKEN_11 = new QName(
            SP11Constants.SP_NS, SPConstants.WSS_X509_PKCS7_TOKEN11, SP11Constants.SP_PREFIX);

    public static final QName WSS_X509_PKI_PATH_V1_TOKEN_11 = new QName(
            SP11Constants.SP_NS, SPConstants.WSS_X509_PKI_PATH_V1_TOKEN11, SP11Constants.SP_PREFIX);

    public static final QName ISSUED_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.ISSUED_TOKEN , SP11Constants.SP_PREFIX);

    public static final QName SUPPORTING_TOKENS = new QName(SP11Constants.SP_NS,
            SPConstants.SUPPORTING_TOKENS , SP11Constants.SP_PREFIX);

    public static final QName SIGNED_SUPPORTING_TOKENS = new QName(
            SP11Constants.SP_NS, SPConstants.SIGNED_SUPPORTING_TOKENS , SP11Constants.SP_PREFIX);

    public static final QName ENDORSING_SUPPORTING_TOKENS = new QName(
            SP11Constants.SP_NS, SPConstants.ENDORSING_SUPPORTING_TOKENS , SP11Constants.SP_PREFIX);

    public static final QName SIGNED_ENDORSING_SUPPORTING_TOKENS = new QName(
            SP11Constants.SP_NS, SPConstants.SIGNED_ENDORSING_SUPPORTING_TOKENS,
            SP11Constants.SP_PREFIX);

    public static final QName PROTECTION_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.PROTECTION_TOKEN, SP11Constants.SP_PREFIX);

    public static final QName ASYMMETRIC_BINDING = new QName(SP11Constants.SP_NS,
            SPConstants.ASYMMETRIC_BINDING, SP11Constants.SP_PREFIX);
    
    public static final QName SYMMETRIC_BINDING = new QName(SP11Constants.SP_NS,
            SPConstants.SYMMETRIC_BINDING, SP11Constants.SP_PREFIX);

    public static final QName INITIATOR_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.INITIATOR_TOKEN , SP11Constants.SP_PREFIX);

    public static final QName RECIPIENT_TOKEN = new QName(SP11Constants.SP_NS,
            SPConstants.RECIPIENT_TOKEN , SP11Constants.SP_PREFIX);

    public static final QName ENCRYPT_SIGNATURE = new QName(SP11Constants.SP_NS,
            SPConstants.ENCRYPT_SIGNATURE , SP11Constants.SP_PREFIX);

    public static final QName PROTECT_TOKENS = new QName(SP11Constants.SP_NS,
            SPConstants.PROTECT_TOKENS, SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_KEY_IDENTIFIRE_REFERENCE = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_KEY_IDENTIFIRE_REFERENCE ,
            SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_ISSUER_SERIAL_REFERENCE = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_ISSUER_SERIAL_REFERENCE,
            SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_EMBEDDED_TOKEN_REFERENCE = new QName(
            SP11Constants.SP_NS,SPConstants.REQUIRE_EMBEDDED_TOKEN_REFERENCE,
            SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_THUMBPRINT_REFERENCE = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_THUMBPRINT_REFERENCE , SP11Constants.SP_PREFIX);


    public static final QName MUST_SUPPORT_REF_KEY_IDENTIFIER = new QName(
            SP11Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_KEY_IDENTIFIER , SP11Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_ISSUER_SERIAL = new QName(
            SP11Constants.SP_NS,SPConstants.MUST_SUPPORT_REF_ISSUER_SERIAL, SP11Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_EXTERNAL_URI = new QName(
            SP11Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_EXTERNAL_URI , SP11Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_EMBEDDED_TOKEN = new QName(
            SP11Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_EMBEDDED_TOKEN, SP11Constants.SP_PREFIX);
    
    public static final QName MUST_SUPPORT_REF_THUMBPRINT = new QName(
            SP11Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_THUMBPRINT, SP11Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_REF_ENCRYPTED_KEY = new QName(
            SP11Constants.SP_NS, SPConstants.MUST_SUPPORT_REF_ENCRYPTED_KEY, SP11Constants.SP_PREFIX);

    public static final QName WSS10 = new QName(SP11Constants.SP_NS, SPConstants.WSS10 ,
            SP11Constants.SP_PREFIX);

    public static final QName WSS11 = new QName(SP11Constants.SP_NS, SPConstants.WSS11,
            SP11Constants.SP_PREFIX);

    public static final QName TRUST_10 = new QName(SP11Constants.SP_NS, SPConstants.TRUST_10,
            SP11Constants.SP_PREFIX);


    public static final QName REQUIRE_SIGNATURE_CONFIRMATION = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_SIGNATURE_CONFIRMATION ,
            SP11Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_CLIENT_CHALLENGE = new QName(
            SP11Constants.SP_NS, SPConstants.MUST_SUPPORT_CLIENT_CHALLENGE, SP11Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_SERVER_CHALLENGE = new QName(
            SP11Constants.SP_NS,SPConstants.MUST_SUPPORT_SERVER_CHALLENGE , SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_CLIENT_ENTROPY = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_CLIENT_ENTROPY, SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_SERVER_ENTROPY = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_SERVER_ENTROPY, SP11Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_ISSUED_TOKENS = new QName(
            SP11Constants.SP_NS, SPConstants.MUST_SUPPORT_ISSUED_TOKENS , SP11Constants.SP_PREFIX);

    public static final QName ISSUER = new QName(SP11Constants.SP_NS, SPConstants.ISSUER ,
            SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_DERIVED_KEYS = new QName(SP11Constants.SP_NS,
            SPConstants.REQUIRE_DERIVED_KEYS, SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_EXTERNAL_URI_REFERNCE = new QName(
            SP11Constants.SP_NS,SPConstants.REQUIRE_EXTERNAL_URI_REFERNCE, SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_EXTERNAL_REFERNCE = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_EXTERNAL_REFERNCE , SP11Constants.SP_PREFIX);

    public static final QName REQUIRE_INTERNAL_REFERNCE = new QName(
            SP11Constants.SP_NS, SPConstants.REQUIRE_INTERNAL_REFERNCE , SP11Constants.SP_PREFIX);

    public static final QName REQUEST_SECURITY_TOKEN_TEMPLATE = new QName(
            SP11Constants.SP_NS, SPConstants.REQUEST_SECURITY_TOKEN_TEMPLATE,
            SP11Constants.SP_PREFIX);

    public static final QName SC10_SECURITY_CONTEXT_TOKEN = new QName(
            SP11Constants.SP_NS, SPConstants.SC10_SECURITY_CONTEXT_TOKEN , SP11Constants.SP_PREFIX);

    public static final QName BOOTSTRAP_POLICY = new QName(SP11Constants.SP_NS,
            SPConstants.BOOTSTRAP_POLICY , SP11Constants.SP_PREFIX);

    public final static QName XPATH = new QName(SP11Constants.SP_NS, SPConstants.XPATH_EXPR,
            SP11Constants.SP_PREFIX);
    
    public static final QName HEADER = new QName(SP11Constants.SP_NS, "Header");

    public static final QName BODY = new QName(SP11Constants.SP_NS, "Body");
    
    public static int getInclusionFromAttributeValue(String value ) {
        
        if (INCLUDE_ALWAYS.equals(value)) {
            return SPConstants.INCLUDE_TOEKN_ALWAYS;
        } else if (INCLUDE_ALWAYS_TO_RECIPIENT.equals(value)) {
            return SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT;
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
                return SP11Constants.INCLUDE_ALWAYS;
            case SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT:
                return SP11Constants.INCLUDE_ALWAYS_TO_RECIPIENT;
            case SPConstants.INCLUDE_TOKEN_NEVER:
                return SP11Constants.INCLUDE_NEVER;
            case SPConstants.INCLUDE_TOKEN_ONCE:
                return SP11Constants.INCLUDE_ONCE;
            default :
                return null;
        }
        
    }

}
