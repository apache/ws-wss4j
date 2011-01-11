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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Class OpenSAMLUtil provides static helper methods for the OpenSaml library
 * <p/>
 * Created on May 18, 2009
 */
public class OpenSAMLUtil {
    private static final Log log = LogFactory.getLog(OpenSAMLUtil.class);

    private static XMLObjectBuilderFactory builderFactory;
    private static MarshallerFactory marshallerFactory;
    private static UnmarshallerFactory unmarshallerFactory;
    private static boolean samlEngineInitialized = false;

    /**
     * Initialise the SAML library
     */
    public synchronized static void initSamlEngine() {
        if (!samlEngineInitialized) {
            log.debug("Initilizing the opensaml2 library...");
            try {
                DefaultBootstrap.bootstrap();
                builderFactory = Configuration.getBuilderFactory();
                marshallerFactory = Configuration.getMarshallerFactory();
                unmarshallerFactory = Configuration.getUnmarshallerFactory();
                samlEngineInitialized = true;
                log.debug("opensaml2 library bootstrap complete");
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
        XMLObject xmlObject = null;
        try {
            xmlObject = unmarshaller.unmarshall(root);
        } catch (UnmarshallingException ex) {
            throw new WSSecurityException("Error unmarshalling a SAML assertion", ex);
        }

        if (xmlObject instanceof org.opensaml.saml1.core.Assertion) {
            log.debug("OpenSAMLUtil: found SAML 1 Assertion");
        } else if (xmlObject instanceof org.opensaml.saml2.core.Assertion) {
            log.debug("OpenSAMLUtil: found SAML 2 Assertion");            
        } else {
            log.debug("OpenSAMLUtil: found unexpected type " + xmlObject.getClass().getName());
        }

        return xmlObject;
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
        try {
            element = marshaller.marshall(xmlObject);
        } catch (MarshallingException ex) {
            throw new WSSecurityException("Error marshalling a SAML assertion", ex);
        }

        // Sign the assertion if the signature element is present.
        if (xmlObject instanceof org.opensaml.saml2.core.Assertion) {
            org.opensaml.saml2.core.Assertion saml2 = (org.opensaml.saml2.core.Assertion) xmlObject;
            // if there is a signature, but it hasn't already been signed
            if (saml2.getSignature() != null) {
                log.debug("Signing SAML v2.0 assertion...");
                try {
                    Signer.signObject(saml2.getSignature());
                } catch (SignatureException ex) {
                    throw new WSSecurityException("Error signing a SAML assertion", ex);
                }
            }
        } else if (xmlObject instanceof org.opensaml.saml1.core.Assertion) {
            org.opensaml.saml1.core.Assertion saml1 = (org.opensaml.saml1.core.Assertion) xmlObject;
            // if there is a signature, but it hasn't already been signed
            if (saml1.getSignature() != null) {
                log.debug("Signing SAML v1.1 assertion...");
                try {
                    Signer.signObject(saml1.getSignature());
                } catch (SignatureException ex) {
                    throw new WSSecurityException("Error signing a SAML assertion", ex);
                }
            }
        }

        // Reparent the document. This makes sure that the resulting element will be compatible
        // with the user-supplied document in the future (for example, when we want to add this
        // element that dom).
        if (doc != null) {
            log.debug("Reparenting the SAML token dom to type: " + doc.getClass().getName());
            Node importedNode = doc.importNode(element, true);
            element = (Element) importedNode;
        }

        return element;
    }
    
    /**
     * Method buildSignature ...
     *
     * @return Signature
     */
    public static Signature buildSignature() {
        return (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Method buildXMLObject ...
     *
     * @param objectQName of type QName
     * @return XMLObject
     */
    public static XMLObject buildXMLObject(QName objectQName) {
        XMLObjectBuilder builder = builderFactory.getBuilder(objectQName);
        if (builder == null) {
            log.fatal("Unable to retrieve builder for object QName " + objectQName);
            return null;
        }
        return 
            builder.buildObject(
                 objectQName.getNamespaceURI(), 
                 objectQName.getLocalPart(), 
                 objectQName.getPrefix()
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
     * Validate the conditions
     *
     * @param notBefore of type DateTime
     * @param notAfter  of type DateTime
     */
    public static void validateConditions(DateTime notBefore, DateTime notAfter) {
        // Make sure that notBefore is before notAfter
        log.debug("Validating notBefore and notAfter");
        if (notBefore.isAfter(notAfter)) {
            throw new IllegalStateException(
                "The value of notBefore may not be after the value of notAfter"
            );
        }
    }

    /**
     * Get the Assertion ID
     *
     * @param envelope of type Element
     * @param elemName of type String
     * @param nmSpace  of type String
     * @return the Assertion ID
     * @throws WSSecurityException
     */
    public static String getAssertionId(
        Element envelope, 
        String elemName, 
        String nmSpace
    ) throws WSSecurityException {
        Element assertionElement = 
            (Element) WSSecurityUtil.findElement(envelope, elemName, nmSpace);

        try {
            AssertionWrapper assertion = new AssertionWrapper(assertionElement);
            return assertion.getId();
        } catch (Exception e1) {
            log.error(e1);
            throw new WSSecurityException(
                    WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig", null, e1);
        }
    }
}
