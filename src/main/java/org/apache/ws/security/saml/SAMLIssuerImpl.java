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

import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.OpenSAMLUtil;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.Loader;

import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Properties;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
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

    private AssertionWrapper sa = null;

    private Document instanceDoc = null;

    private Properties properties = null;

    private Crypto issuerCrypto = null;
    private String issuerKeyPassword = null;
    private String issuerKeyName = null;

    private boolean senderVouches = true;

    private String[] confirmationMethods = new String[1];
    
    private WSSConfig wssConfig = WSSConfig.getNewInstance();
    
    private String samlVersion = null;
    
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
        
        samlVersion = properties.getProperty("org.apache.ws.security.saml.version");

        String confMethod = properties.getProperty("org.apache.ws.security.saml.confirmationMethod");
        if ("senderVouches".equals(confMethod)) {
            if ("1.1".equalsIgnoreCase(samlVersion)) {
                confirmationMethods[0] = SAML1Constants.CONF_SENDER_VOUCHES;
            } else if ("2.0".equalsIgnoreCase(samlVersion)) {
                confirmationMethods[0] = SAML2Constants.SBJ_CONFIRMATION_SENDER_VOUCHES;
            } else {
                // Default to SAML 1.1
                confirmationMethods[0] = SAML1Constants.CONF_SENDER_VOUCHES;
            }
        } else if ("keyHolder".equals(confMethod)) {
            if ("1.1".equalsIgnoreCase(samlVersion)) {
                confirmationMethods[0] = SAML1Constants.CONF_HOLDER_KEY;
                senderVouches = false;
            } else if ("2.0".equalsIgnoreCase(samlVersion)) {
                confirmationMethods[0] = SAML2Constants.SBJ_CONFIRMATION_HOLDER_OF_KEY;
            } else {
                // Default to SAML 1.1
                confirmationMethods[0] = SAML1Constants.CONF_HOLDER_KEY;
                senderVouches = false;
            }
        } else {
            // throw something here - this is a mandatory property
            throw new IllegalStateException(
                "No value provided in saml configuration for confirmation method"
            );
        }
    }

    /**
     * Creates a new AssertionWrapper.
     *
     * @return a new AssertionWrapper.
     */
    public AssertionWrapper newAssertion() throws WSSecurityException {
        
        log.debug(
          "Entering AssertionWrapper.newAssertion() ... creating SAML v" 
          + samlVersion + " token"
        );

        String issuer = properties.getProperty("org.apache.ws.security.saml.issuer");
        String samlCallbackClassname = 
            properties.getProperty("org.apache.ws.security.saml.callback");
        Class<?> callbackClass = null;
        try {
            callbackClass = Loader.loadClass(samlCallbackClassname);
        } catch (ClassNotFoundException ex) {
            throw new WSSecurityException(ex.getMessage(), ex);
        }

        // Create a new SAMLParms with all of the information from the properties file.
        SAMLParms samlParms = new SAMLParms();
        samlParms.setIssuer(issuer);
        samlParms.setSamlVersion(samlVersion);
        try {
            samlParms.setCallbackHandler((CallbackHandler)callbackClass.newInstance());
        } catch (InstantiationException ex) {
            throw new WSSecurityException(ex.getMessage(), ex);
        } catch (IllegalAccessException ex) {
            throw new WSSecurityException(ex.getMessage(), ex);
        }

        sa = new AssertionWrapper(samlParms);
        
        if (!senderVouches) {
            //
            // Create the signature
            //
            Signature signature = OpenSAMLUtil.buildSignature();
            signature.setCanonicalizationAlgorithm(
                SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
            );
            
            // prepare to sign the SAML token
            X509Certificate[] issuerCerts = issuerCrypto.getCertificates(issuerKeyName);

            String sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
            String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
            log.debug("automatic sig algo detection: " + pubKeyAlgo);
            if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_DSA;
            }
            PrivateKey privateKey = null;
            try {
                privateKey = issuerCrypto.getPrivateKey(issuerKeyName, issuerKeyPassword);
            } catch (Exception ex) {
                throw new WSSecurityException(ex.getMessage(), ex);
            }

            signature.setSignatureAlgorithm(sigAlgo);

            BasicX509Credential signingCredential = new BasicX509Credential();
            if (issuerCerts.length == 1) {
                signingCredential.setEntityCertificate(issuerCerts[0]);
            } else {
                signingCredential.setEntityCertificateChain(Arrays.asList(issuerCerts));
            }
            signingCredential.setPrivateKey(privateKey);
            signingCredential.setEntityId(issuer);

            signature.setSigningCredential(signingCredential);

            X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
            if (sendKeyValue) {
                kiFactory.setEmitPublicKeyValue(true);
            } else {
                kiFactory.setEmitEntityCertificate(true);
            }
            try {
                KeyInfo keyInfo = kiFactory.newInstance().generate(signingCredential);
                signature.setKeyInfo(keyInfo);
            } catch (org.opensaml.xml.security.SecurityException ex) {
                throw new WSSecurityException(
                    "Error generating KeyInfo from signing credential", ex
                );
            }

            // add the signature to the assertion
            sa.setSignature(signature);
        }

        return sa;
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
