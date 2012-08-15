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

package org.apache.ws.security.saml.ext;

import javax.security.auth.callback.CallbackHandler;

import org.opensaml.common.SAMLVersion;

/**
 * Class SAMLParms is a parameter bean that is used to pass raw material from
 * the <code>AssertionWrapper</code> to the SAML builders during statement
 * creation.
 * <p/>
 * Created on May 18, 2009
 */
public class SAMLParms {
    private String issuer;
    private SAMLVersion samlVersion = SAMLVersion.VERSION_11;
    private CallbackHandler samlCallbackHandler;

    /**
     * Method getIssuer returns the issuer of this SAMLParms object.
     *
     * @return the issuer (type String) of this SAMLParms object.
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Method setIssuer sets the issuer of this SAMLParms object.
     *
     * @param issuer the issuer of this SAMLParms object.
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    
    /**
     * Get the SAML Version of the SAML Assertion to generate
     * @return the SAML Version of the SAML Assertion to generate
     */
    public SAMLVersion getSAMLVersion() {
        return samlVersion;
    }
    
    /**
     * Set the SAML Version of the SAML Assertion to generate
     * @param samlVersion the SAML Version of the SAML Assertion to generate
     */
    public void setSAMLVersion(SAMLVersion samlVersion) {
        this.samlVersion = samlVersion;
    }
    
    /**
     * Get the CallbackHandler instance used to populate the SAML Assertion content
     * @return the CallbackHandler instance used to populate the SAML Assertion content
     */
    public CallbackHandler getCallbackHandler() {
        return samlCallbackHandler;
    }
    
    /**
     * Set the CallbackHandler instance used to populate the SAML Assertion content
     * @param samlCallbackHandler the CallbackHandler instance used to populate the 
     *        SAML Assertion content
     */
    public void setCallbackHandler(CallbackHandler samlCallbackHandler) {
        this.samlCallbackHandler = samlCallbackHandler;
    }

}
