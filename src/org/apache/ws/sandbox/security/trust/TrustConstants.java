/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.ws.sandbox.security.trust;

/**
 * @author Malinda Kaushalye
 * @author Ruchith Fernando
 * @version 1.0
 *          <p/>
 *          TrustConstants is the class where all the constants of the WS-Trust implementation are kept.
 *          Primarily all the namespaces, prefixes and local names of the tokens are kept here.
 *          Then all the codes used in message exchanges are also listed here.
 *          all the configuration parameters are also kept here.
 */

public class TrustConstants {

    private static final String NS_YEAR_PREFIX = "http://schemas.xmlsoap.org/ws/2005/02/";
    public static final String WST_NS = NS_YEAR_PREFIX + "trust";
    public static final String WST_PREFIX = "wst";

    //WS-Policy related constants
    public static final String WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public static final String WSP_PREFIX = "wsp";	
    public static final String APPLIESTO_LN = "AppliesTo";
    
    //WS-Addressing related constants
    public static final String WSA_NS = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public static final String WSA_PREFIX = "wsa";
    public static final String ENDPOINT_REFERENCE_LN = "EndpointReference";
    public static final String ADDRESS_LN = "Address";
	
    //Utility related constants
    public static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String WSU_PREFIX = "wsu";
    public static final String CREATED_LN = "Created";
    public static final String EXPIRES_LN = "Expires";
    public static final String ID_ATTR = "Id";
    
    //local names of the token used in WS-Trust
    public static final String TOKEN_TYPE_LN = "TokenType";
    public static final String REQUEST_TYPE_LN = "RequestType";
    public static final String KEY_TYPE_LN = "KeyType";
    public static final String KEY_SIZE_LN = "KeySize";
    public static final String LIFE_TIME_LN = "Lifetime";
    public static final String BASE_LN = "Base";
    public static final String STATUS_LN = "Status";
    public static final String CODE_LN = "Code";
    public static final String REASON_LN = "Reason";
    public static final String RENEWING_LN = "Renewing";
    public static final String RENEW_TARGET_LN = "RenewTarget";
    public static final String CANCEL_TARGET_LN = "CancelTarget";
    public static final String REQUESTED_TOKEN_CANCELLED_LN = "RequestedTokenCancelled";
    public static final String ALLOWPOSTDATING_LN = "AllowPostdating";
    public static final String BINARY_SECRET_LN= "BinarySecret";
    public static final String ENTROPY_LN= "Entropy";
    public static final String CLAIMS_LN = "Claims";
    public static final String COMPUTED_KEY_LN = "ComputedKey";
    
    public static final String REQUEST_SECURITY_TOKEN_LN = "RequestSecurityToken";
    public static final String REQUEST_SECURITY_TOKEN_RESPONSE_LN = "RequestSecurityTokenResponse";
    public static final String REQUESTED_SECURITY_TOKEN_LN = "RequestedSecurityToken";
    public static final String REQUESTED_PROOF_TOKEN_LN = "RequestedProofToken";

    //Attributes
    public static final String CONTEXT_ATTR = "Context";
    public static final String BINARY_SECRET_TYPE_ATTR = "Type";
    public static final String CLAIMS_DIALECT_ATTR = "Dialect";
    public static final String RENEWING_ALLOW_ATTR = "Allow";
    public static final String RENEWING_OK_ATTR = "OK";
    
    // The request type is specified using following URIs as specified in the WS-Trust specification
    public static final String ISSUE_SECURITY_TOKEN = WST_NS + "/Issue";
    public static final String RENEW_SECURITY_TOKEN = WST_NS + "/Renew";
    public static final String VALIDATE_SECURITY_TOKEN = WST_NS + "/Validate";
    public static final String CANCEL_SECURITY_TOKEN = WST_NS + "/Cancel";

    //RSTRs
    public static final String RSTR_PREFIX = WST_NS + "/RSTR";
    public static final String ISSUE_SECURITY_TOKEN_RSTR = RSTR_PREFIX + "/Issue";
    public static final String RENEW_SECURITY_TOKEN_RSTR = RSTR_PREFIX + "/Renew";
    public static final String VALIDATE_SECURITY_TOKEN_RSTR = RSTR_PREFIX + "/Validate";
    public static final String CANCEL_SECURITY_TOKEN_RSTR = RSTR_PREFIX + "/Cancel";

    //RSTs
    public static final String RST_PREFIX = WST_NS + "/RST";
    public static final String ISSUE_SECURITY_TOKEN_RST = RST_PREFIX + "/Issue";
    public static final String RENEW_SECURITY_TOKEN_RST = RST_PREFIX + "/Renew";
    public static final String VALIDATE_SECURITY_TOKEN_RST = RST_PREFIX + "/Validate";
    public static final String CANCEL_SECURITY_TOKEN_RST = RST_PREFIX + "/Cancel";
    
    //STATUS
    public static final String STATUS_PREFIX = WST_NS + "/status";
    public static final String STATUS_VALID = STATUS_PREFIX + "/valid";
    public static final String STATUS_INVALID = STATUS_PREFIX + "/invalid";

    //Token yypes
    public static final String TOKEN_TYPE_RSTR_STATUS = RSTR_PREFIX + "/Status";
    
    //Binary secret types
    public static final String BINARY_SECRET_ASYMMETRIC_KEY = WST_NS + "/AsymmetricKey";
	public static final String BINARY_SECRET_SYMMETRIC_KEY = WST_NS + "/SymmetricKey";
	public static final String BINARY_SECRET_NONCE_VAL= WST_NS + "/Nonce";
    
    //COmputedKey types
    public static final String COMPUTED_KEY_PSHA1 = WST_NS + "/CK/PSHA1"; 
  
    //For STS there should be an issuer class specified in the STS.properties
    public static final String ISSUER_CLASS = "org.apache.ws.axis.security.trust.service.SecurityTokenService.issuerClass";
    //For STS there should be a renewer class specified in the STS.properties
    public static final String RENEWER_CLASS = "org.apache.ws.axis.security.trust.service.SecurityTokenService.renewerClass";
    //For STS there should be a validator class specified in the STS.properties
    public static final String VALIDATOR_CLASS = "org.apache.ws.axis.security.trust.service.SecurityTokenService.validatorClass";

    //In the request, The token type can be specified in the client-config
    public static final String TOKEN_TYPE = "TokenType";
    //The request type , issue/renew or validate 
    public static final String REQUEST_TYPE = "RequestType";

    //for BASED_ON_X509
    public static final String BASE_CERT_FILE = "BaseCertFile";
    public static final String USER = "user";//alias of the certificate

    //for BASED_ON_USERNAME_TOKEN
    public static final String UNT_USER = "UNTUser";
    public static final String UNT_PWCALLBACK_CLASS = "passwordCallbackClass";

    //requester class
    public static final String REQUESTER_CLASS = "requesterClass";
}

