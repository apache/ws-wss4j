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
package org.apache.ws.security.trust;

/**
 * @author Malinda Kaushalye
 * @version 1.0
 *          <p/>
 *          TrustConstants is the class where all the constants of the WS-Trust implementation are kept.
 *          Primarily all the namespaces, prefixes and local names of the tokens are kept here.
 *          Then all the codes used in message exchanges are also listed here.
 *          all the configuration parameters are also kept here.
 */

public class TrustConstants {

    //local names of the token used in WS-Trust
    public static final String SECURITY_CONTEXT_TOKEN_RESPONSE_LN = "SecurityContextTokenResponse";
    public static final String REQUEST_SECURITY_TOKEN_RESPONSE_LN = "RequestSecurityTokenResponse";//trust
    public static final String TOKEN_TYPE_LN = "TokenType";
    public static final String REQUEST_TYPE_LN = "RequestType";
    public static final String KEY_TYPE_LN = "KeyType";
    public static final String KEY_SIZE_LN = "KeySize";

    public static final String LIFE_TIME_LN = "Lifetime";
    public static final String CREATED_LN = "Created";
    public static final String EXPIRES_LN = "Expires";
    public static final String BASE_LN = "Base";
    public static final String STATUS_LN = "Status";
    public static final String CODE_LN = "Code";
    public static final String REASON_LN = "Reason";
    public static final String RENEWING_LN = "Renewing";
    public static final String ALLOWPOSTDATING_LN = "AllowPostdating";
    public static final String APPLIESTO_LN = "AppliesTo";
    public static final String BINARY_SECRET_LN= "BinarySecret";

    public static final String REQUEST_SECURITY_TOKEN_LN = "RequestSecurityToken";
    public static final String REQUESTED_SECURITY_TOKEN_LN = "RequestedSecurityToken";
    public static final String REQUESTED_PROOF_TOKEN_LN = "RequestedProofToken";
    public static final String SECURITY_CONTEXT_TOKEN_LN = "SecurityContextToken";

    // The request type is specified using following URIs as specified in the WS-Trust specification
    public static final String ISSUE_SECURITY_TOKEN = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue";//RequestTypeEnum._value1.toString();//"http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue";
    public static final String RENEW_SECURITY_TOKEN = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Renew";
    public static final String VALIDATE_SECURITY_TOKEN = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Validate";

    public static final String ISSUE_SECURITY_TOKEN_RSTR = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue";
    public static final String RENEW_SECURITY_TOKEN_RSTR = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Renew";
    public static final String VALIDATE_SECURITY_TOKEN_RSTR = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Validate";

    public static final String ISSUE_SECURITY_TOKEN_RST = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue";
    public static final String RENEW_SECURITY_TOKEN_RST = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Renew";
    public static final String VALIDATE_SECURITY_TOKEN_RST = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Validate";
  
  
//  public static final URI ISSUE_SECURITY_TOKEN_URI = new URI("http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue");
//  public static final URI RENEW_SECURITY_TOKEN_URI = new URI("http://schemas.xmlsoap.org/ws/2004/04/security/trust/Renew");
//  public static final URI VALIDATE_SECURITY_TOKEN_URI = new URI("http://schemas.xmlsoap.org/ws/2004/04/security/trust/Validate"); 
    public static final String WST_NS = "http://schemas.xmlsoap.org/ws/2004/04/trust";
    public static final String WSP_NS = "http://schemas.xmlsoap.org/ws/2002/12/policy";

    public static final String WST_PREFIX = "wst";
    public static final String WSP_PREFIX = "wsp";

    //For STS there should be an issuer class specified in the STS.properties
    public static final String ISSUER_CLASS = "org.apache.ws.axis.security.trust.service.SecurityTokenService.issuerClass";
    //    For STS there should be a renewer class specified in the STS.properties
    public static final String RENEWER_CLASS = "org.apache.ws.axis.security.trust.service.SecurityTokenService.renewerClass";
    //    For STS there should be a validator class specified in the STS.properties
    public static final String VALIDATOR_CLASS = "org.apache.ws.axis.security.trust.service.SecurityTokenService.validatorClass";

    //In the request, The token type can be specified in the client-config
    public static final String TOKEN_TYPE = "TokenType";
    //The request type , issue/renew or validate 
    public static final String REQUEST_TYPE = "RequestType";
    
//    ...commented.... no need of having these params.
// architectural change in the STSClientHandler. Now we have more distributed requesters....
//    //basedon params
//    public static final String BASED_ON="BasedOn";
//    //based on values
//    public static final String BASED_ON_X509="X509Certificate";
//    public static final String BASED_ON_USERNAME_TOKEN="UsernameToken";
//    public static final String BASED_ON_SAML="SAML";
    
    //for BASED_ON_X509
    public static final String BASE_CERT_FILE = "BaseCertFile";
    public static final String USER = "user";//alias of the certificate

    //for BASED_ON_USERNAME_TOKEN
    public static final String UNT_USER = "UNTUser";
    public static final String UNT_PWCALLBACK_CLASS = "passwordCallbackClass";

    //requester class
    public static final String REQUESTER_CLASS = "requesterClass";
}

