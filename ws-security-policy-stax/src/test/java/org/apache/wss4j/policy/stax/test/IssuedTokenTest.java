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

package org.apache.wss4j.policy.stax.test;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.impl.securityToken.KerberosServiceSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.SamlSecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.KerberosTokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.saml.common.SAMLVersion;
import org.apache.wss4j.policy.stax.PolicyEnforcer;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SamlTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;

import javax.xml.namespace.QName;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class IssuedTokenTest extends AbstractPolicyTestBase {

    private static final String samlPolicyString =
            "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
            "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
            "<sp:InitiatorToken>\n" +
            "   <wsp:Policy>\n" +
            "       <sp:IssuedToken>\n" +
            "           <sp:IssuerName>http://initiatorTokenIssuer.com</sp:IssuerName>\n" +
            "           <sp:RequestSecurityTokenTemplate xmlns:t=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">\n" +
            "               <t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType>\n" +
            "               <t:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey</t:KeyType>\n" +
            "               <t:Claims Dialect=\"http://schemas.xmlsoap.org/ws/2005/05/identity\"\n" +
            "                   xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">\n" +
            "                   <ic:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email\"/>\n" +
            "                   <ic:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\"/>\n" +
            "                   <ic:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/phone\" Optional=\"true\"/>\n" +
            "               </t:Claims>\n" +
            "           </sp:RequestSecurityTokenTemplate>\n" +
            "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
            "               <sp:RequireExternalReference/>\n" +
            "           </wsp:Policy>\n" +
            "       </sp:IssuedToken>\n" +
            "   </wsp:Policy>\n" +
            "</sp:InitiatorToken>\n" +
            "<sp:RecipientToken>\n" +
            "   <wsp:Policy>\n" +
            "       <sp:IssuedToken>\n" +
            "           <sp:IssuerName>http://recipientTokenIssuer.com</sp:IssuerName>\n" +
            "           <sp:RequestSecurityTokenTemplate/>\n" +
            "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
            "               <sp:RequireExternalReference/>\n" +
            "           </wsp:Policy>\n" +
            "       </sp:IssuedToken>\n" +
            "   </wsp:Policy>\n" +
            "</sp:RecipientToken>\n" +
            "   <sp:AlgorithmSuite>\n" +
            "       <wsp:Policy>\n" +
            "           <sp:Basic256/>\n" +
            "       </wsp:Policy>\n" +
            "   </sp:AlgorithmSuite>\n" +
            "</wsp:Policy>\n" +
            "</sp:AsymmetricBinding>";

    @Test
    public void testPolicyWithSAMLToken() throws Exception {

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(samlPolicyString);

        SAMLCallback samlCallback = new SAMLCallback();
        samlCallback.setSamlVersion(SAMLVersion.VERSION_20);
        samlCallback.setIssuer("http://initiatorTokenIssuer.com");
        SubjectBean subjectBean = new SubjectBean();
        samlCallback.setSubject(subjectBean);

        List<AttributeStatementBean> attributeStatementBeans = new ArrayList<AttributeStatementBean>();
        List<AttributeBean> attributeBeans = new ArrayList<AttributeBean>();
        List<Object> attributeValues = new ArrayList<Object>();
        attributeValues.add("test@example.com");
        attributeBeans.add(new AttributeBean("email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email", attributeValues));
        attributeValues.clear();
        attributeValues.add("Proper");
        attributeBeans.add(new AttributeBean("surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", attributeValues));
        attributeStatementBeans.add(new AttributeStatementBean(subjectBean, attributeBeans));
        samlCallback.setAttributeStatementData(attributeStatementBeans);

        SamlAssertionWrapper samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent initiatorTokenSecurityEvent = new SamlTokenSecurityEvent();
        SamlSecurityTokenImpl securityToken = 
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        samlCallback.setIssuer("http://recipientTokenIssuer.com");
        samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent recipientTokenSecurityEvent = new SamlTokenSecurityEvent();
        securityToken = 
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyWithSAMLTokenWrongIssuer() throws Exception {

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(samlPolicyString);

        SAMLCallback samlCallback = new SAMLCallback();
        samlCallback.setSamlVersion(SAMLVersion.VERSION_20);
        samlCallback.setIssuer("http://initiatorTokenIssuer.com");
        SubjectBean subjectBean = new SubjectBean();
        samlCallback.setSubject(subjectBean);

        List<AttributeStatementBean> attributeStatementBeans = new ArrayList<AttributeStatementBean>();
        List<AttributeBean> attributeBeans = new ArrayList<AttributeBean>();
        List<Object> attributeValues = new ArrayList<Object>();
        attributeValues.add("test@example.com");
        attributeBeans.add(new AttributeBean("email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email", attributeValues));
        attributeValues.clear();
        attributeValues.add("Proper");
        attributeBeans.add(new AttributeBean("surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", attributeValues));
        attributeStatementBeans.add(new AttributeStatementBean(subjectBean, attributeBeans));
        samlCallback.setAttributeStatementData(attributeStatementBeans);

        SamlAssertionWrapper samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent initiatorTokenSecurityEvent = new SamlTokenSecurityEvent();
        SamlSecurityTokenImpl securityToken =
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        SamlTokenSecurityEvent recipientTokenSecurityEvent = new SamlTokenSecurityEvent();
        securityToken = 
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "IssuerName in Policy (http://recipientTokenIssuer.com) didn't match with the one in the IssuedToken (http://initiatorTokenIssuer.com)");
        }
    }

    @Test
    public void testPolicyWithSAMLTokenWrongTokenType() throws Exception {

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(samlPolicyString);

        SAMLCallback samlCallback = new SAMLCallback();
        samlCallback.setSamlVersion(SAMLVersion.VERSION_11);
        samlCallback.setIssuer("http://initiatorTokenIssuer.com");
        SubjectBean subjectBean = new SubjectBean();
        samlCallback.setSubject(subjectBean);

        List<AttributeStatementBean> attributeStatementBeans = new ArrayList<AttributeStatementBean>();
        List<AttributeBean> attributeBeans = new ArrayList<AttributeBean>();
        List<Object> attributeValues = new ArrayList<Object>();
        attributeValues.add("test@example.com");
        attributeBeans.add(new AttributeBean("email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email", attributeValues));
        attributeValues.clear();
        attributeValues.add("Proper");
        attributeBeans.add(new AttributeBean("surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", attributeValues));
        attributeStatementBeans.add(new AttributeStatementBean(subjectBean, attributeBeans));
        samlCallback.setAttributeStatementData(attributeStatementBeans);

        SamlAssertionWrapper samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent initiatorTokenSecurityEvent = new SamlTokenSecurityEvent();
        SamlSecurityTokenImpl securityToken =
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        samlCallback.setIssuer("http://recipientTokenIssuer.com");
        samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent recipientTokenSecurityEvent = new SamlTokenSecurityEvent();
        securityToken = 
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "Policy enforces SAML V2.0 token but got 1.1");
        }
    }

    @Test
    public void testPolicyWithSAMLTokenWrongKeyType() throws Exception {

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(samlPolicyString.replaceFirst("PublicKey", "SymmetricKey"));

        SAMLCallback samlCallback = new SAMLCallback();
        samlCallback.setSamlVersion(SAMLVersion.VERSION_20);
        samlCallback.setIssuer("http://initiatorTokenIssuer.com");
        SubjectBean subjectBean = new SubjectBean();
        samlCallback.setSubject(subjectBean);

        List<AttributeStatementBean> attributeStatementBeans = new ArrayList<AttributeStatementBean>();
        List<AttributeBean> attributeBeans = new ArrayList<AttributeBean>();
        List<Object> attributeValues = new ArrayList<Object>();
        attributeValues.add("test@example.com");
        attributeBeans.add(new AttributeBean("email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email", attributeValues));
        attributeValues.clear();
        attributeValues.add("Proper");
        attributeBeans.add(new AttributeBean("surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", attributeValues));
        attributeStatementBeans.add(new AttributeStatementBean(subjectBean, attributeBeans));
        samlCallback.setAttributeStatementData(attributeStatementBeans);

        SamlAssertionWrapper samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent initiatorTokenSecurityEvent = new SamlTokenSecurityEvent();
        SamlSecurityTokenImpl securityToken =
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        samlCallback.setIssuer("http://recipientTokenIssuer.com");
        samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent recipientTokenSecurityEvent = new SamlTokenSecurityEvent();
        securityToken = 
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "Policy enforces SAML token with a symmetric key");
        }
    }

    @Test
    public void testPolicyWithSAMLTokenMissingClaimType() throws Exception {

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(samlPolicyString);

        SAMLCallback samlCallback = new SAMLCallback();
        samlCallback.setSamlVersion(SAMLVersion.VERSION_20);
        samlCallback.setIssuer("http://initiatorTokenIssuer.com");
        SubjectBean subjectBean = new SubjectBean();
        samlCallback.setSubject(subjectBean);

        List<AttributeStatementBean> attributeStatementBeans = new ArrayList<AttributeStatementBean>();
        List<AttributeBean> attributeBeans = new ArrayList<AttributeBean>();
        List<Object> attributeValues = new ArrayList<Object>();
        attributeValues.add("test@example.com");
        attributeBeans.add(new AttributeBean("email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email", attributeValues));
        attributeStatementBeans.add(new AttributeStatementBean(subjectBean, attributeBeans));
        samlCallback.setAttributeStatementData(attributeStatementBeans);

        SamlAssertionWrapper samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent initiatorTokenSecurityEvent = new SamlTokenSecurityEvent();
        SamlSecurityTokenImpl securityToken =
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        samlCallback.setIssuer("http://recipientTokenIssuer.com");
        samlAssertionWrapper = createSamlAssertionWrapper(samlCallback);

        SamlTokenSecurityEvent recipientTokenSecurityEvent = new SamlTokenSecurityEvent();
        securityToken = 
            new SamlSecurityTokenImpl(
                    samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null,
                    WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference, null);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "Attribute http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname not found in the SAMLAssertion");
        }
    }

    private static final String kerberosPolicyString =
            "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                    "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                    "<sp:InitiatorToken>\n" +
                    "   <wsp:Policy>\n" +
                    "       <sp:IssuedToken>\n" +
                    "           <sp:IssuerName>http://initiatorTokenIssuer.com</sp:IssuerName>\n" +
                    "           <sp:RequestSecurityTokenTemplate xmlns:t=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">\n" +
                    "               <t:TokenType>http://docs.oasisopen.org/wss/oasiswss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1</t:TokenType>\n" +
                    "           </sp:RequestSecurityTokenTemplate>\n" +
                    "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                    "               <sp:RequireExternalReference/>\n" +
                    "           </wsp:Policy>\n" +
                    "       </sp:IssuedToken>\n" +
                    "   </wsp:Policy>\n" +
                    "</sp:InitiatorToken>\n" +
                    "<sp:RecipientToken>\n" +
                    "   <wsp:Policy>\n" +
                    "       <sp:IssuedToken>\n" +
                    "           <sp:IssuerName>http://recipientTokenIssuer.com</sp:IssuerName>\n" +
                    "           <sp:RequestSecurityTokenTemplate/>\n" +
                    "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                    "               <sp:RequireExternalReference/>\n" +
                    "           </wsp:Policy>\n" +
                    "       </sp:IssuedToken>\n" +
                    "   </wsp:Policy>\n" +
                    "</sp:RecipientToken>\n" +
                    "   <sp:AlgorithmSuite>\n" +
                    "       <wsp:Policy>\n" +
                    "           <sp:Basic256/>\n" +
                    "       </wsp:Policy>\n" +
                    "   </sp:AlgorithmSuite>\n" +
                    "</wsp:Policy>\n" +
                    "</sp:AsymmetricBinding>";

    @Test
    public void testPolicyWithKerberosToken() throws Exception {

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(kerberosPolicyString);

        KerberosTokenSecurityEvent initiatorTokenSecurityEvent = new KerberosTokenSecurityEvent();
        initiatorTokenSecurityEvent.setIssuerName("http://initiatorTokenIssuer.com");
        KerberosServiceSecurityTokenImpl securityToken = new KerberosServiceSecurityTokenImpl(
                null, null, null,
                "http://docs.oasisopen.org/wss/oasiswss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1",
                "1", WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        KerberosTokenSecurityEvent recipientTokenSecurityEvent = new KerberosTokenSecurityEvent();
        recipientTokenSecurityEvent.setIssuerName("http://recipientTokenIssuer.com");
        securityToken = new KerberosServiceSecurityTokenImpl(
                null, null, null,
                "http://docs.oasisopen.org/wss/oasiswss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1",
                "1", WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyWithKerberosTokenWrongTokenType() throws Exception {

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(kerberosPolicyString);

        KerberosTokenSecurityEvent initiatorTokenSecurityEvent = new KerberosTokenSecurityEvent();
        initiatorTokenSecurityEvent.setIssuerName("http://initiatorTokenIssuer.com");
        KerberosServiceSecurityTokenImpl securityToken = new KerberosServiceSecurityTokenImpl(
                null, null, null,
                "http://docs.oasisopen.org/wss/oasiswss-kerberos-tokenprofile-1.1#GSS_Kerberosv5_AP_REQ",
                "1", WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        KerberosTokenSecurityEvent recipientTokenSecurityEvent = new KerberosTokenSecurityEvent();
        recipientTokenSecurityEvent.setIssuerName("http://recipientTokenIssuer.com");
        securityToken = new KerberosServiceSecurityTokenImpl(
                null, null, null,
                "http://docs.oasisopen.org/wss/oasiswss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1",
                "1", WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Policy enforces Kerberos token of type http://docs.oasisopen.org/wss/oasiswss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1 but got http://docs.oasisopen.org/wss/oasiswss-kerberos-tokenprofile-1.1#GSS_Kerberosv5_AP_REQ");
        }
    }
}
