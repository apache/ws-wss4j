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

import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.opensaml.xml.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;

/**
 * Class OpenSAMLUtil provides static helper methods for the OpenSaml library
 * <p/>
 * Created on May 18, 2009
 */
public final class OpenSAMLUtil {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(OpenSAMLUtil.class);

    private static XMLObjectBuilderFactory builderFactory;
    private static MarshallerFactory marshallerFactory;
    private static UnmarshallerFactory unmarshallerFactory;
    private static boolean samlEngineInitialized = false;
    
    private OpenSAMLUtil() {
        // Complete
    }

    /**
     * Initialise the SAML library
     */
    public static synchronized void initSamlEngine() {
        if (!samlEngineInitialized) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Initializing the opensaml2 library...");
            }
            try {
                OpenSAMLBootstrap.bootstrap();
                builderFactory = Configuration.getBuilderFactory();
                marshallerFactory = Configuration.getMarshallerFactory();
                unmarshallerFactory = Configuration.getUnmarshallerFactory();
                samlEngineInitialized = true;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("opensaml2 library bootstrap complete");
                }
            } catch (ConfigurationException e) {
                LOG.error(
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
        if (root == null) {
            LOG.debug("Attempting to unmarshal a null element!");
            throw new WSSecurityException("Error unmarshalling a SAML assertion");
        }
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(root);
        if (unmarshaller == null) {
            LOG.debug("Unable to find an unmarshaller for element: " + root.getLocalName());
            throw new WSSecurityException("Error unmarshalling a SAML assertion");
        }
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
        return toDom(xmlObject, doc, true);
    }
    
    /**
     * Convert a SAML Assertion from a XMLObject to a DOM Element
     *
     * @param xmlObject of type XMLObject
     * @param doc  of type Document
     * @param signObject whether to sign the XMLObject during marshalling
     * @return Element
     * @throws MarshallingException
     * @throws SignatureException
     */
    public static Element toDom(
        XMLObject xmlObject, 
        Document doc,
        boolean signObject
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
    
            if (signObject) {
                signXMLObject(xmlObject);
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
    
    private static void signXMLObject(XMLObject xmlObject) throws WSSecurityException {
        if (xmlObject instanceof org.opensaml.saml1.core.Response) {
            org.opensaml.saml1.core.Response response = 
                    (org.opensaml.saml1.core.Response)xmlObject;
            
            // Sign any Assertions
            if (response.getAssertions() != null) {
                for (org.opensaml.saml1.core.Assertion assertion : response.getAssertions()) {
                    signObject(assertion.getSignature());
                }
            }
            
            signObject(response.getSignature());
        } else if (xmlObject instanceof org.opensaml.saml2.core.Response) {
            org.opensaml.saml2.core.Response response = 
                    (org.opensaml.saml2.core.Response)xmlObject;
            
            // Sign any Assertions
            if (response.getAssertions() != null) {
                for (org.opensaml.saml2.core.Assertion assertion : response.getAssertions()) {
                    signObject(assertion.getSignature());
                }
            }
            
            signObject(response.getSignature());
        } else if (xmlObject instanceof org.opensaml.saml2.core.Assertion) {
            org.opensaml.saml2.core.Assertion saml2 = 
                    (org.opensaml.saml2.core.Assertion) xmlObject;
            
            signObject(saml2.getSignature());
        } else if (xmlObject instanceof org.opensaml.saml1.core.Assertion) {
            org.opensaml.saml1.core.Assertion saml1 = 
                    (org.opensaml.saml1.core.Assertion) xmlObject;
            
            signObject(saml1.getSignature());
        } else if (xmlObject instanceof org.opensaml.saml2.core.RequestAbstractType) {
            org.opensaml.saml2.core.RequestAbstractType request = 
                    (org.opensaml.saml2.core.RequestAbstractType) xmlObject;
            
            
            signObject(request.getSignature());
        } else if (xmlObject instanceof org.opensaml.saml1.core.Request) {
            org.opensaml.saml1.core.Request request = 
                    (org.opensaml.saml1.core.Request) xmlObject;
            
            signObject(request.getSignature());
        }
    }
    
    private static void signObject(Signature signature) throws WSSecurityException {
        if (signature != null) {
            try {
                Signer.signObject(signature);
            } catch (SignatureException ex) {
                throw new WSSecurityException("Error signing a SAML assertion", ex);
            }
        }
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
            LOG.error(
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
