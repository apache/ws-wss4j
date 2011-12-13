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

import org.apache.ws.security.saml.ext.bean.AttributeStatementBean;
import org.apache.ws.security.saml.ext.bean.AuthDecisionStatementBean;
import org.apache.ws.security.saml.ext.bean.AuthenticationStatementBean;
import org.apache.ws.security.saml.ext.bean.ConditionsBean;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.opensaml.common.SAMLVersion;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import java.util.ArrayList;
import java.util.List;


/**
 * Class SAMLCallback will be called by the <code>AssertionWrapper</code> during the creation
 * of SAML statements (authentication, attribute, and authz decision). Alternatively, the
 * "assertionElement" member of this class can be set instead, for a pre-existing SAML
 * Assertion.
 */
public class SAMLCallback implements Callback {
    
    /**
     * The SAML Version of the Assertion to create
     */
    private SAMLVersion samlVersion;
    
    /**
     * SAML subject representation
     */
    private SubjectBean subject;
    
    /**
     * The issuer of the Assertion
     */
    private String issuer;
    
    /**
     * SAML Conditions representation
     */
    private ConditionsBean conditions;

    /**
     * A list of <code>AuthenticationStatementBean</code> values
     */
    private List<AuthenticationStatementBean> authenticationStatementData;

    /**
     * A list of <code>AttributeStatementBean</code> values
     */
    private List<AttributeStatementBean> attributeStatementData;

    /**
     * A list of <code>AuthDecisionStatementBean</code> values
     */
    private List<AuthDecisionStatementBean> authDecisionStatementData;
    
    /**
     * A DOM Element representation of this SAML Assertion
     */
    private Element assertionElement;

    /**
     * Constructor SAMLCallback creates a new SAMLCallback instance.
     */
    public SAMLCallback() {
        authenticationStatementData = new ArrayList<AuthenticationStatementBean>();
        attributeStatementData = new ArrayList<AttributeStatementBean>();
        authDecisionStatementData = new ArrayList<AuthDecisionStatementBean>();
    }

    /**
     * Method getAuthenticationStatementData returns the authenticationStatementData of this 
     * SAMLCallback object.
     *
     * @return the authenticationStatementData (type List<AuthenticationStatementBean>) of 
     *         this SAMLCallback object.
     */
    public List<AuthenticationStatementBean> getAuthenticationStatementData() {
        return authenticationStatementData;
    }

    /**
     * Method setAuthenticationStatementData sets the authenticationStatementData of this 
     * SAMLCallback object.
     *
     * @param authenticationStatementData the authenticationStatementData of this 
     *        SAMLCallback object.
     */
    public void setAuthenticationStatementData(
        List<AuthenticationStatementBean> authenticationStatementData
    ) {
        this.authenticationStatementData = authenticationStatementData;
    }

    /**
     * Method getAttributeStatementData returns the attributeStatementData of this 
     * SAMLCallback object.
     *
     * @return the attributeStatementData (type List<AttributeStatementBean>) of this 
     *         SAMLCallback object.
     */
    public List<AttributeStatementBean> getAttributeStatementData() {
        return attributeStatementData;
    }

    /**
     * Method setAttributeStatementData sets the attributeStatementData of this SAMLCallback object.
     *
     * @param attributeStatementData the attributeStatementData of this SAMLCallback object.
     */
    public void setAttributeStatementData(List<AttributeStatementBean> attributeStatementData) {
        this.attributeStatementData = attributeStatementData;
    }

    /**
     * Method getAuthDecisionStatementData returns the authDecisionStatementData of this 
     * SAMLCallback object.
     *
     * @return the authDecisionStatementData (type List<AuthDecisionStatementBean>) of this 
     *         SAMLCallback object.
     */
    public List<AuthDecisionStatementBean> getAuthDecisionStatementData() {
        return authDecisionStatementData;
    }

    /**
     * Method setAuthDecisionStatementData sets the authDecisionStatementData of this 
     * SAMLCallback object.
     *
     * @param authDecisionStatementData the authDecisionStatementData of this 
     *        SAMLCallback object.
     */
    public void setAuthDecisionStatementData(
        List<AuthDecisionStatementBean> authDecisionStatementData
    ) {
        this.authDecisionStatementData = authDecisionStatementData;
    }

    /**
     * Method getSubject returns the subject of this SAMLCallback object.
     *
     * @return the subject (type SubjectBean) of this SAMLCallback object.
     */
    public SubjectBean getSubject() {
        return subject;
    }

    /**
     * Method setSubject sets the subject of this SAMLCallback object.
     *
     * @param subject the subject of this SAMLCallback object.
     */
    public void setSubject(SubjectBean subject) {
        this.subject = subject;
    }
    
    /**
     * Method getIssuer returns the issuer of this SAMLCallback object.
     *
     * @return the issuer of this SAMLCallback object.
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Method setIssuer sets the issuer of this SAMLCallback object.
     *
     * @param issuer the issuer of this SAMLCallback object.
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    
    /**
     * Method getConditions returns the conditions of this SAMLCallback object.
     *
     * @return the conditions (type ConditionsBean) of this SAMLCallback object.
     */
    public ConditionsBean getConditions() {
        return conditions;
    }

    /**
     * Method setConditions sets the conditions of this SAMLCallback object.
     *
     * @param conditions the conditions of this SAMLCallback object.
     */
    public void setConditions(ConditionsBean conditions) {
        this.conditions = conditions;
    }
    
    /**
     * Set the SAMLVersion of the assertion to create
     * @param samlVersion the SAMLVersion of the assertion to create
     */
    public void setSamlVersion(SAMLVersion samlVersion) {
        this.samlVersion = samlVersion;
    }
    
    /**
     * Get the SAMLVersion of the assertion to create
     * @return the SAMLVersion of the assertion to create
     */
    public SAMLVersion getSamlVersion() {
        return samlVersion;
    }
    
    /**
     * Set the DOM representation of this SAML Assertion
     * @param assertionElement the DOM representation of this SAML Assertion
     */
    public void setAssertionElement(Element assertionElement) {
        this.assertionElement = assertionElement;
    }
    
    /**
     * Get the DOM representation of this SAML Assertion
     * @return the DOM representation of this SAML Assertion
     */
    public Element getAssertionElement() {
        return assertionElement;
    }
}
