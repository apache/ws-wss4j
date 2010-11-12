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

package org.apache.ws.security.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Properties;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;

/**
 * Builds a WS SAML Assertion and inserts it into the SOAP Envelope. Refer to
 * the WS specification, SAML Token profile
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class SAMLIssuerImpl implements SAMLIssuer {

    private static final Log log = LogFactory.getLog(SAMLIssuerImpl.class.getName());

    private SAMLAssertion sa = null;

    private Document instanceDoc = null;

    private Properties properties = null;

    private Crypto issuerCrypto = null;
    private String issuerKeyPassword = null;
    private String issuerKeyName = null;

    private boolean senderVouches = true;

    private String[] confirmationMethods = new String[1];
    private Crypto userCrypto = null;
    private String username = null;
    
    private WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();
    
    private KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM");
    
    /**
     * Flag indicating what format to put the subject's key material in when
     * NOT using Sender Vouches as the confirmation method.  The default is
     * to use ds:X509Data and include the entire certificate.  If this flag
     * is set to true, a ds:KeyValue is used instead with just the key material.
     */
    private boolean sendKeyValue = false;

    /**
     * Constructor.
     */
    public SAMLIssuerImpl() {
    }

    public SAMLIssuerImpl(Properties prop) {
        /*
         * if no properties .. just return an instance, the rest will be done
         * later or this instance is just used to handle certificate
         * conversions in this implementation
         */
        if (prop == null) {
            return;
        }
        properties = prop;

        String cryptoProp =
                properties.getProperty("org.apache.ws.security.saml.issuer.cryptoProp.file");
        if (cryptoProp != null) {
            issuerCrypto = CryptoFactory.getInstance(cryptoProp);
            issuerKeyName =
                    properties.getProperty("org.apache.ws.security.saml.issuer.key.name");
            issuerKeyPassword =
                    properties.getProperty("org.apache.ws.security.saml.issuer.key.password");
        }
        
        String sendKeyValueProp =
                properties.getProperty("org.apache.ws.security.saml.issuer.sendKeyValue");
        if (sendKeyValueProp != null) {
            sendKeyValue = Boolean.valueOf(sendKeyValueProp).booleanValue();
        }

        if ("senderVouches"
                .equals(properties.getProperty("org.apache.ws.security.saml.confirmationMethod"))) {
            confirmationMethods[0] = SAMLSubject.CONF_SENDER_VOUCHES;
        } else if (
                "keyHolder".equals(properties.getProperty("org.apache.ws.security.saml.confirmationMethod"))) {
            confirmationMethods[0] = SAMLSubject.CONF_HOLDER_KEY;
            senderVouches = false;
        } else {
            // throw something here - this is a mandatory property
        }
    }

    /**
     * Creates a new <code>SAMLAssertion</code>.
     * <p/>
     * <p/>
     * A complete <code>SAMLAssertion</code> is constructed.
     *
     * @return SAMLAssertion
     */
    public SAMLAssertion newAssertion() { // throws Exception {
        log.debug("Begin add SAMLAssertion token...");

        /*
         * if (senderVouches == false && userCrypto == null) { throw
         * exception("need user crypto data to insert key") }
         */
        // Issuer must enable crypto functions to get the issuer's certificate
        String issuer =
                properties.getProperty("org.apache.ws.security.saml.issuer");
        String name =
                properties.getProperty("org.apache.ws.security.saml.subjectNameId.name");
        String qualifier =
                properties.getProperty("org.apache.ws.security.saml.subjectNameId.qualifier");
        try {
            SAMLNameIdentifier nameId =
                    new SAMLNameIdentifier(name, qualifier, "");
            String subjectIP = null;
            String authMethod = null;
            if ("password"
                    .equals(properties.getProperty("org.apache.ws.security.saml.authenticationMethod"))) {
                authMethod =
                        SAMLAuthenticationStatement.AuthenticationMethod_Password;
            }
            Date authInstant = new Date();
            Collection<?> bindings = null;

            SAMLSubject subject =
                    new SAMLSubject(nameId,
                            Arrays.asList(confirmationMethods),
                            null,
                            null);
            SAMLStatement[] statements =
                    {
                        new SAMLAuthenticationStatement(subject,
                                authMethod,
                                authInstant,
                                subjectIP,
                                null,
                                bindings)};
            sa =
                    new SAMLAssertion(issuer,
                            null,
                            null,
                            null,
                            null,
                            Arrays.asList(statements));

            if (!senderVouches) {
                KeyInfo keyInfo = null;
                try {
                    X509Certificate[] certs =
                            userCrypto.getCertificates(username);
                    String keyInfoUri = 
                        wssConfig.getIdAllocator().createSecureId("KI-", keyInfo);
                    if (sendKeyValue) {
                        PublicKey key = certs[0].getPublicKey();
                        KeyValue keyValue = keyInfoFactory.newKeyValue(key);
                        keyInfo = 
                            keyInfoFactory.newKeyInfo(
                                java.util.Collections.singletonList(keyValue), keyInfoUri
                            );
                    } else {
                        X509Data x509Data = 
                            keyInfoFactory.newX509Data(java.util.Collections.singletonList(certs[0]));
                        keyInfo = 
                            keyInfoFactory.newKeyInfo(
                                java.util.Collections.singletonList(x509Data), keyInfoUri
                            );
                    }
                    
                    Element keyInfoParent = instanceDoc.createElement("KeyInfoParent");
                    XMLStructure structure = new DOMStructure(keyInfoParent);
                    keyInfo.marshal(structure, null);
                    Element keyInfoElement = (Element)keyInfoParent.getFirstChild();
                    subject.setKeyInfo(keyInfoElement);
                } catch (WSSecurityException ex) {
                    if (log.isDebugEnabled()) {
                        log.debug(ex.getMessage(), ex);
                    }
                    return null;
                } catch (MarshalException ex) {
                    if (log.isDebugEnabled()) {
                        log.debug(ex.getMessage(), ex);
                    }
                    return null;
                } catch (KeyException ex) {
                    if (log.isDebugEnabled()) {
                        log.debug(ex.getMessage(), ex);
                    }
                    return null;
                }
                // prepare to sign the SAML token
                try {
                    X509Certificate[] issuerCerts =
                            issuerCrypto.getCertificates(issuerKeyName);

                    String sigAlgo = WSConstants.RSA_SHA1;
                    String pubKeyAlgo =
                            issuerCerts[0].getPublicKey().getAlgorithm();
                    log.debug("automatic sig algo detection: " + pubKeyAlgo);
                    if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                        sigAlgo = WSConstants.DSA;
                    }
                    java.security.Key issuerPK =
                            issuerCrypto.getPrivateKey(issuerKeyName,
                                    issuerKeyPassword);
                    sa.sign(sigAlgo, issuerPK, Arrays.asList(issuerCerts));
                } catch (WSSecurityException ex) {
                    if (log.isDebugEnabled()) {
                        log.debug(ex.getMessage(), ex);
                    }
                    return null;
                } catch (Exception ex) {
                    if (log.isDebugEnabled()) {
                        log.debug(ex.getMessage(), ex);
                    }
                    return null;
                }
            }
        } catch (SAMLException ex) {
            if (log.isDebugEnabled()) {
                log.debug(ex.getMessage(), ex);
            }
            throw new RuntimeException(ex.toString(), ex);
        }
        return sa;
    }

    /**
     * @param userCrypto The userCrypto to set.
     */
    public void setUserCrypto(Crypto userCrypto) {
        this.userCrypto = userCrypto;
    }

    /**
     * @param username The username to set.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return Returns the issuerCrypto.
     */
    public Crypto getIssuerCrypto() {
        return issuerCrypto;
    }

    /**
     * @return Returns the issuerKeyName.
     */
    public String getIssuerKeyName() {
        return issuerKeyName;
    }

    /**
     * @return Returns the issuerKeyPassword.
     */
    public String getIssuerKeyPassword() {
        return issuerKeyPassword;
    }

    /**
     * @return Returns the senderVouches.
     */
    public boolean isSenderVouches() {
        return senderVouches;
    }

    /**
     * @param instanceDoc The instanceDoc to set.
     */
    public void setInstanceDoc(Document instanceDoc) {
        this.instanceDoc = instanceDoc;
    }
}
