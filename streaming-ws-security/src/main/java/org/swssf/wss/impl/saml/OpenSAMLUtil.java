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

package org.swssf.wss.impl.saml;

import javax.xml.namespace.QName;

import org.opensaml.xml.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.swssf.wss.ext.WSSecurityException;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;

/**
 * Class OpenSAMLUtil provides static helper methods for the OpenSaml library
 * <p/>
 * Created on May 18, 2009
 */
public class OpenSAMLUtil {
    private static final org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(OpenSAMLUtil.class);

    private static XMLObjectBuilderFactory builderFactory;
    private static MarshallerFactory marshallerFactory;
    private static UnmarshallerFactory unmarshallerFactory;
    private static boolean samlEngineInitialized = false;

    /**
     * Initialise the SAML library
     */
    public synchronized static void initSamlEngine() {
        if (!samlEngineInitialized) {
            if (log.isDebugEnabled()) {
                log.debug("Initilizing the opensaml2 library...");
            }
            try {
                OpenSAMLBootstrap.bootstrap();
                builderFactory = Configuration.getBuilderFactory();
                marshallerFactory = Configuration.getMarshallerFactory();
                unmarshallerFactory = Configuration.getUnmarshallerFactory();
                samlEngineInitialized = true;
                if (log.isDebugEnabled()) {
                    log.debug("opensaml2 library bootstrap complete");
                }
            } catch (ConfigurationException e) {
                log.error(
                    "Unable to bootstrap the opensaml2 library - all SAML operations will fail", 
                    e
                );
            }
        }
    }

    /**
     * Convert a SAML Assertion from a DOM Element to an XMLObject
     *
     * @param root of type Element
     * @return XMLObject
     * @throws UnmarshallingException
     */
    public static XMLObject fromDom(Element root) throws WSSecurityException {
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(root);
        try {
            return unmarshaller.unmarshall(root);
        } catch (UnmarshallingException ex) {
            throw new WSSecurityException("Error unmarshalling a SAML assertion", ex);
        }
    }

    /**
     * Convert a SAML Assertion from a XMLObject to a DOM Element
     *
     * @param xmlObject of type XMLObject
     * @param doc  of type Document
     * @return Element
     * @throws MarshallingException
     * @throws SignatureException
     */
    public static Element toDom(
        XMLObject xmlObject, 
        Document doc
    ) throws WSSecurityException {
        Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        Element element = null;
        DocumentFragment frag = doc == null ? null : doc.createDocumentFragment();
        try {
            if (frag != null) {
                while (doc.getFirstChild() != null) {
                    frag.appendChild(doc.removeChild(doc.getFirstChild()));
                }
            }
            try {
                if (doc == null) {
                    element = marshaller.marshall(xmlObject);
                } else {
                    element = marshaller.marshall(xmlObject, doc);
                } 
            } catch (MarshallingException ex) {
                throw new WSSecurityException("Error marshalling a SAML assertion", ex);
            }
    
            // Sign the assertion if the signature element is present.
            if (xmlObject instanceof org.opensaml.saml2.core.Assertion) {
                org.opensaml.saml2.core.Assertion saml2 = 
                    (org.opensaml.saml2.core.Assertion) xmlObject;
                // if there is a signature, but it hasn't already been signed
                if (saml2.getSignature() != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Signing SAML v2.0 assertion...");
                    }
                    try {
                        Signer.signObject(saml2.getSignature());
                    } catch (SignatureException ex) {
                        throw new WSSecurityException("Error signing a SAML assertion", ex);
                    }
                }
            } else if (xmlObject instanceof org.opensaml.saml1.core.Assertion) {
                org.opensaml.saml1.core.Assertion saml1 = 
                    (org.opensaml.saml1.core.Assertion) xmlObject;
                // if there is a signature, but it hasn't already been signed
                if (saml1.getSignature() != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Signing SAML v1.1 assertion...");
                    }
                    try {
                        Signer.signObject(saml1.getSignature());
                    } catch (SignatureException ex) {
                        throw new WSSecurityException("Error signing a SAML assertion", ex);
                    }
                }
            }
        } finally {
            if (frag != null) {
                while (doc.getFirstChild() != null) {
                    doc.removeChild(doc.getFirstChild());
                }
                doc.appendChild(frag);
            }
        }
        return element;
    }
    
    /**
     * Method buildSignature ...
     *
     * @return Signature
     */
    @SuppressWarnings("unchecked")
    public static Signature buildSignature() {
        QName qName = Signature.DEFAULT_ELEMENT_NAME;
        XMLObjectBuilder<Signature> builder = builderFactory.getBuilder(qName);
        if (builder == null) {
            log.error(
                "Unable to retrieve builder for object QName " 
                + qName
            );
            return null;
        }
        return 
            (Signature)builder.buildObject(
                 qName.getNamespaceURI(), qName.getLocalPart(), qName.getPrefix()
             );
    }
    
    /**
     * Method isMethodSenderVouches ...
     *
     * @param confirmMethod of type String
     * @return boolean
     */
    public static boolean isMethodSenderVouches(String confirmMethod) {
        return 
            confirmMethod != null && confirmMethod.startsWith("urn:oasis:names:tc:SAML:") 
                && confirmMethod.endsWith(":cm:sender-vouches");
    }
    
    /**
     * Method isMethodHolderOfKey ...
     *
     * @param confirmMethod of type String
     * @return boolean
     */
    public static boolean isMethodHolderOfKey(String confirmMethod) {
        return 
            confirmMethod != null && confirmMethod.startsWith("urn:oasis:names:tc:SAML:") 
                && confirmMethod.endsWith(":cm:holder-of-key");
    }

}
