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
package org.apache.wss4j.stax.test.saml;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.ActionBean;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.AuthDecisionStatementBean;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.SubjectLocalityBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAMLCallbackHandlerImpl implements CallbackHandler {

    public enum Statement {
        AUTHN, ATTR, AUTHZ
    }

    private String subjectName = "uid=joe,ou=people,ou=saml-demo,o=example.com";
    private String subjectQualifier = "www.example.com";
    private String confirmationMethod = SAML1Constants.CONF_SENDER_VOUCHES;
    private X509Certificate[] certs;
    private Statement statement = Statement.AUTHN;
    private KeyInfoBean.CERT_IDENTIFIER certIdentifier = KeyInfoBean.CERT_IDENTIFIER.X509_CERT;
    private byte[] ephemeralKey = null;
    private String issuer = null;
    private String issuerFormat;
    private Version samlVersion = Version.SAML_11;

    private String subjectNameIDFormat = null;
    private String subjectLocalityIpAddress = null;
    private String subjectLocalityDnsAddress = null;
    private String resource = null;
    private List<Object> customAttributeValues = null;
    private ConditionsBean conditions = null;

    private boolean signAssertion = true;

    public SAMLCallbackHandlerImpl() {
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks[0] instanceof SAMLCallback) {
            try {
                SAMLCallback samlCallback = (SAMLCallback) callbacks[0];
                KeyStore keyStore = KeyStore.getInstance("jks");
                InputStream input = this.getClass().getClassLoader().getResourceAsStream("saml/issuer.jks");
                keyStore.load(input, "default".toCharArray());
                input.close();
                
                Merlin crypto = new Merlin();
                crypto.setKeyStore(keyStore);
                samlCallback.setIssuerCrypto(crypto);
                samlCallback.setIssuerKeyName("samlissuer");
                samlCallback.setIssuerKeyPassword("default");
                samlCallback.setSignAssertion(this.signAssertion);
                samlCallback.setIssuer(issuer);
                samlCallback.setIssuerFormat(issuerFormat);

                if (conditions != null) {
                    samlCallback.setConditions(conditions);
                }

                SubjectBean subjectBean =
                        new SubjectBean(subjectName, subjectQualifier, confirmationMethod);
                if (subjectNameIDFormat != null) {
                    subjectBean.setSubjectNameIDFormat(subjectNameIDFormat);
                }

                if (SAML1Constants.CONF_HOLDER_KEY.equals(confirmationMethod)
                        || SAML2Constants.CONF_HOLDER_KEY.equals(confirmationMethod)) {
                    try {
                        KeyInfoBean keyInfo = createKeyInfo();
                        subjectBean.setKeyInfo(keyInfo);
                    } catch (Exception ex) {
                        throw new IOException("Problem creating KeyInfo: " + ex.getMessage());
                    }
                }
                samlCallback.setSubject(subjectBean);

                if (getSamlVersion() == Version.SAML_11) {
                    samlCallback.setSamlVersion(Version.SAML_11);
                    createAndSetStatement(subjectBean, samlCallback);
                } else {
                    samlCallback.setSamlVersion(Version.SAML_20);
                    createAndSetStatement(null, samlCallback);
                }
            } catch (Exception e) {
                throw new IOException(e);
            }
        }
    }

    /**
     * Note that the SubjectBean parameter should be null for SAML2.0
     */
    protected void createAndSetStatement(SubjectBean subjectBean, SAMLCallback callback) {
        if (statement == Statement.AUTHN) {
            AuthenticationStatementBean authBean = new AuthenticationStatementBean();
            if (subjectBean != null) {
                authBean.setSubject(subjectBean);
            }
            if (subjectLocalityIpAddress != null || subjectLocalityDnsAddress != null) {
                SubjectLocalityBean subjectLocality = new SubjectLocalityBean();
                subjectLocality.setIpAddress(subjectLocalityIpAddress);
                subjectLocality.setDnsAddress(subjectLocalityDnsAddress);
                authBean.setSubjectLocality(subjectLocality);
            }
            authBean.setAuthenticationMethod("Password");
            callback.setAuthenticationStatementData(Collections.singletonList(authBean));
        } else if (statement == Statement.ATTR) {
            AttributeStatementBean attrBean = new AttributeStatementBean();
            AttributeBean attributeBean = new AttributeBean();
            if (subjectBean != null) {
                attrBean.setSubject(subjectBean);
                attributeBean.setSimpleName("role");
                attributeBean.setQualifiedName("http://custom-ns");
            } else {
                attributeBean.setQualifiedName("role");
            }
            if (customAttributeValues != null) {
                attributeBean.setAttributeValues(customAttributeValues);
            } else {
                List<Object> attributes = new ArrayList<Object>();
                attributes.add("user");
                attributeBean.setAttributeValues(attributes);
            }
            attrBean.setSamlAttributes(Collections.singletonList(attributeBean));
            callback.setAttributeStatementData(Collections.singletonList(attrBean));
        } else {
            AuthDecisionStatementBean authzBean = new AuthDecisionStatementBean();
            if (subjectBean != null) {
                authzBean.setSubject(subjectBean);
            }
            ActionBean actionBean = new ActionBean();
            actionBean.setContents("Read");
            authzBean.setActions(Collections.singletonList(actionBean));
            authzBean.setResource("endpoint");
            authzBean.setDecision(AuthDecisionStatementBean.Decision.PERMIT);
            authzBean.setResource(resource);
            callback.setAuthDecisionStatementData(Collections.singletonList(authzBean));
        }
    }

    protected KeyInfoBean createKeyInfo() throws Exception {
        KeyInfoBean keyInfo = new KeyInfoBean();
        if (statement == Statement.AUTHN) {
            keyInfo.setCertificate(certs[0]);
            keyInfo.setCertIdentifer(certIdentifier);
        } else if (statement == Statement.ATTR) {
            // Build a new Document
            DocumentBuilderFactory docBuilderFactory =
                    DocumentBuilderFactory.newInstance();
            docBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            Document doc = docBuilder.newDocument();

            // Create an Encrypted Key
            WSSecEncryptedKey encrKey = new WSSecEncryptedKey();
            encrKey.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
            encrKey.setUseThisCert(certs[0]);
            encrKey.prepare(doc, null);
            ephemeralKey = encrKey.getEphemeralKey();
            keyInfo.setEphemeralKey(ephemeralKey);
            Element encryptedKeyElement = encrKey.getEncryptedKeyElement();

            // Append the EncryptedKey to a KeyInfo element
            Element keyInfoElement =
                    doc.createElementNS(
                            WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN
                    );
            keyInfoElement.setAttributeNS(
                    WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
            );
            keyInfoElement.appendChild(encryptedKeyElement);

            keyInfo.setElement(keyInfoElement);
        }
        return keyInfo;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public String getSubjectQualifier() {
        return subjectQualifier;
    }

    public void setSubjectQualifier(String subjectQualifier) {
        this.subjectQualifier = subjectQualifier;
    }

    public String getConfirmationMethod() {
        return confirmationMethod;
    }

    public void setConfirmationMethod(String confirmationMethod) {
        this.confirmationMethod = confirmationMethod;
    }

    public X509Certificate[] getCerts() {
        return certs;
    }

    public void setCerts(X509Certificate[] certs) {
        this.certs = certs;
    }

    public Statement getStatement() {
        return statement;
    }

    public void setStatement(Statement statement) {
        this.statement = statement;
    }

    public KeyInfoBean.CERT_IDENTIFIER getCertIdentifier() {
        return certIdentifier;
    }

    public void setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER certIdentifier) {
        this.certIdentifier = certIdentifier;
    }

    public byte[] getEphemeralKey() {
        return ephemeralKey;
    }

    public void setEphemeralKey(byte[] ephemeralKey) {
        this.ephemeralKey = ephemeralKey;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    
    public void setIssuerFormat(String issuerFormat) {
        this.issuerFormat = issuerFormat;
    }

    public boolean isSignAssertion() {
        return signAssertion;
    }

    public void setSignAssertion(boolean signAssertion) {
        this.signAssertion = signAssertion;
    }

    public Version getSamlVersion() {
        return samlVersion;
    }

    public void setSamlVersion(Version samlVersion) {
        this.samlVersion = samlVersion;
    }

    public void setConditions(ConditionsBean conditionsBean) {
        this.conditions = conditionsBean;
    }

    public void setSubjectNameIDFormat(String subjectNameIDFormat) {
        this.subjectNameIDFormat = subjectNameIDFormat;
    }

    public void setSubjectLocality(String ipAddress, String dnsAddress) {
        this.subjectLocalityIpAddress = ipAddress;
        this.subjectLocalityDnsAddress = dnsAddress;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public void setCustomAttributeValues(List<Object> customAttributeValues) {
        this.customAttributeValues = customAttributeValues;
    }
}
