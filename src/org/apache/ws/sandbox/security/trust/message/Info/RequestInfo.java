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
package org.apache.ws.security.trust.message.Info;

import org.apache.ws.security.trust.TrustConstants;

/**
 * @author Malinda Kaushalye
 * Act as a Data Object
 * Usefull to exchange the information about a request.
 * Need more attributes...
 * 
 */
public class RequestInfo {
    
private String requestType;
private String tokenType;
private String baseType;
private String appliesTo;
    
public static final String ISSUE=TrustConstants.ISSUE_SECURITY_TOKEN;
public static final String RENEW=TrustConstants.RENEW_SECURITY_TOKEN;
public static final String VALIDATE=TrustConstants.VALIDATE_SECURITY_TOKEN;

public static final String X509="X509Certificate";
public static final String USERNAME="UsernameToken";
public static final String SAML="SAML";
public static final String CUSTOM="CustomToken";
    /**
     * 
     */
    public RequestInfo() {

    }
    /**
     * Constructor for RequestInfo
     * @param requestType
     * @param tokenType
     * @param baseType
     * @param appliesTo
     */
    public RequestInfo(String requestType,String tokenType,String baseType,String appliesTo) {
        this(requestType,tokenType,baseType);
        this.appliesTo=appliesTo;
    }
    
    /**
     * Constructor for RequestInfo
     * @param requestType
     * @param tokenType
     * @param baseType
     */
    public RequestInfo(String requestType,String tokenType,String baseType) {
        this(requestType,tokenType);
        this.baseType=baseType;
    }
    
    /**
     * Constructor for RequestInfo
     * @param requestType
     * @param tokenType
     */
    public RequestInfo(String requestType,String tokenType) {
        this(requestType);
        this.tokenType=tokenType;        
    }
    /**
     * Constructor for RequestInfo
     * @param requestType
     */
    public RequestInfo(String requestType) {        
        this.requestType=requestType;
    }

/**
 * get RequestType
 * @return
 */
public String getRequestType() {
    return requestType;
}

/**
 * get TokenType
 * @return
 */
public String getTokenType() {
    return tokenType;
}

/**
 * set RequestType
 * @param string
 */
public void setRequestType(String string) {
    this.requestType = string;
}

/**
 * set TokenType
 * @param string
 */
public void setTokenType(String string) {
    tokenType = string;
}

/**
 *  get BaseType
 * @return
 */
public String getBaseType() {
    return baseType;
}

/**
 * set BaseType
 * @param string
 */
public void setBaseType(String string) {
    baseType = string;
}

/**
 * get AppliesTo
 * @return
 */
public String getAppliesTo() {
    return appliesTo;
}

/**
 * set AppliesTo
 * @param string
 */
public void setAppliesTo(String string) {
    appliesTo = string;
}

}
