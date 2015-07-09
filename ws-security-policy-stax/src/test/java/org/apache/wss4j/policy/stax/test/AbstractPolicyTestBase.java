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

import org.apache.neethi.builders.AssertionBuilder;
import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.stax.PolicyEnforcer;
import org.apache.wss4j.policy.stax.PolicyEnforcerFactory;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.impl.securityToken.*;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.xml.security.binding.xmldsig11.ECKeyValueType;
import org.apache.xml.security.binding.xmldsig11.NamedCurveType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

public class AbstractPolicyTestBase extends AbstractTestBase {

    @BeforeClass
    public static void setUp() throws Exception {
        WSProviderConfig.init();
        Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
    }
    
    @AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    protected PolicyEnforcer buildAndStartPolicyEngine(String policyString)
            throws ParserConfigurationException, SAXException, IOException, WSSPolicyException {
        return this.buildAndStartPolicyEngine(policyString, false);
    }

    protected PolicyEnforcer buildAndStartPolicyEngine(String policyString, boolean replacePolicyElement)
            throws ParserConfigurationException, SAXException, IOException, WSSPolicyException {
        return buildAndStartPolicyEngine(policyString, replacePolicyElement, null);
    }

    protected PolicyEnforcer buildAndStartPolicyEngine(
            String policyString, boolean replacePolicyElement, List<AssertionBuilder<Element>> customAssertionBuilders)
            throws ParserConfigurationException, SAXException, IOException, WSSPolicyException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setValidating(false);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(
                this.getClass().getClassLoader().getResourceAsStream("testdata/wsdl/wsdl-template.wsdl"));
        NodeList nodeList = document.getElementsByTagNameNS("*", SPConstants.P_LOCALNAME);

        Document policyDocument = documentBuilder.parse(new ByteArrayInputStream(policyString.getBytes("UTF-8")));
        Node policyNode = document.importNode(policyDocument.getDocumentElement(), true);
        Element element = (Element) nodeList.item(0);
        if (replacePolicyElement) {
            element.getParentNode().replaceChild(element, policyNode);
        } else {
            element.appendChild(policyNode);
        }
        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(document, customAssertionBuilders);
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("", false, null, 0);

        return policyEnforcer;
    }

    public X509SecurityTokenImpl getX509Token(WSSecurityTokenConstants.TokenType tokenType) throws Exception {
        return getX509Token(tokenType, "transmitter");
    }

    public X509SecurityTokenImpl getX509Token(WSSecurityTokenConstants.TokenType tokenType, final String keyAlias) throws Exception {

        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());

        X509SecurityTokenImpl x509SecurityToken =
                new X509SecurityTokenImpl(
                        tokenType, null, null, null, IDGenerator.generateID(null),
                        WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier, null, true) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return keyAlias;
            }
            
            @Override
            public List<QName> getElementPath() {
                List<QName> elementPath = super.getElementPath();
                if (elementPath != null) {
                    return elementPath;
                }
                return Collections.emptyList();
            }
        };
        x509SecurityToken.setSecretKey("", keyStore.getKey(keyAlias, "default".toCharArray()));
        x509SecurityToken.setPublicKey(keyStore.getCertificate(keyAlias).getPublicKey());

        Certificate[] certificates;
        try {
            certificates = keyStore.getCertificateChain(keyAlias);
        } catch (Exception e) {
            throw new XMLSecurityException(e);
        }

        X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
        for (int i = 0; i < certificates.length; i++) {
            Certificate certificate = certificates[i];
            x509Certificates[i] = (X509Certificate) certificate;
        }
        x509SecurityToken.setX509Certificates(x509Certificates);
        return x509SecurityToken;
    }

    public KerberosServiceSecurityTokenImpl getKerberosServiceSecurityToken(WSSecurityTokenConstants.TokenType tokenType) throws Exception {
        return new KerberosServiceSecurityTokenImpl(
                null, null, null, null, IDGenerator.generateID(null),
                WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
    }

    public HttpsSecurityTokenImpl getHttpsSecurityToken(WSSecurityTokenConstants.TokenType tokenType) throws Exception {
        return new HttpsSecurityTokenImpl(getX509Token(tokenType).getX509Certificates()[0]);
    }

    public RsaKeyValueSecurityTokenImpl getRsaKeyValueSecurityToken() throws Exception {
        return new RsaKeyValueSecurityTokenImpl(null, null, null);
    }

    public DsaKeyValueSecurityTokenImpl getDsaKeyValueSecurityToken() throws Exception {
        return new DsaKeyValueSecurityTokenImpl(null, null, null);
    }

    public ECKeyValueSecurityTokenImpl getECKeyValueSecurityToken() throws Exception {
        ECKeyValueType ecKeyValueType = new ECKeyValueType();
        ecKeyValueType.setNamedCurve(new NamedCurveType());
        return new ECKeyValueSecurityTokenImpl(ecKeyValueType, null, null);
    }

    protected String loadResourceAsString(String resource, String encoding) throws IOException {
        InputStreamReader inputStreamReader = new InputStreamReader(this.getClass().getClassLoader().getResourceAsStream(resource), encoding);
        StringBuilder stringBuilder = new StringBuilder();
        int read = 0;
        char[] buffer = new char[1024];
        while ((read = inputStreamReader.read(buffer)) != -1) {
            stringBuilder.append(buffer, 0, read);
        }
        return stringBuilder.toString();
    }

    public static SamlAssertionWrapper createSamlAssertionWrapper(SAMLCallback samlCallback) throws WSSecurityException {
        return new SamlAssertionWrapper(samlCallback);
    }
}
