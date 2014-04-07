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
package org.apache.wss4j.stax.ext;

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.impl.SecurityHeaderOrder;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.securityEvent.*;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.EncryptionPartDef;
import org.apache.xml.security.stax.impl.util.ConcreteLSInput;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.xml.security.utils.ClassLoaderUtils;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class WSSUtils extends XMLSecurityUtils {

    protected WSSUtils() {
        super();
    }

    /**
     * Executes the Callback handling. Typically used to fetch passwords
     *
     * @param callbackHandler
     * @param callback
     * @throws WSSecurityException if the callback couldn't be executed
     */
    public static void doPasswordCallback(CallbackHandler callbackHandler, Callback callback)
            throws WSSecurityException {

        if (callbackHandler == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
        }
        try {
            callbackHandler.handle(new Callback[]{callback});
        } catch (IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    /**
     * Try to get the secret key from a CallbackHandler implementation
     *
     * @param callbackHandler a CallbackHandler implementation
     * @throws WSSecurityException
     */
    public static void doSecretKeyCallback(CallbackHandler callbackHandler, Callback callback, String id)
            throws WSSecurityException {

        if (callbackHandler != null) {
            try {
                callbackHandler.handle(new Callback[]{callback});
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noPassword", e);
            } catch (UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noPassword", e);
            }
        }
    }

    public static String doPasswordDigest(byte[] nonce, String created, String password) throws WSSecurityException {
        try {
            byte[] b1 = nonce != null ? nonce : new byte[0];
            byte[] b2 = created != null ? created.getBytes("UTF-8") : new byte[0];
            byte[] b3 = password.getBytes("UTF-8");
            byte[] b4 = new byte[b1.length + b2.length + b3.length];
            int offset = 0;
            System.arraycopy(b1, 0, b4, offset, b1.length);
            offset += b1.length;

            System.arraycopy(b2, 0, b4, offset, b2.length);
            offset += b2.length;

            System.arraycopy(b3, 0, b4, offset, b3.length);

            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.reset();
            sha.update(b4);
            return new String(Base64.encodeBase64(sha.digest()));
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "decoding.general", e);
        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    public static String getSOAPMessageVersionNamespace(XMLSecEvent xmlSecEvent) {
        XMLSecStartElement xmlSecStartElement = xmlSecEvent.getStartElementAtLevel(1);
        if (xmlSecStartElement != null) {
            if (WSSConstants.TAG_soap11_Envelope.equals(xmlSecStartElement.getName())) {
                return WSSConstants.NS_SOAP11;
            } else if (WSSConstants.TAG_soap12_Envelope.equals(xmlSecStartElement.getName())) {
                return WSSConstants.NS_SOAP12;
            }
        }
        return null;
    }

    public static boolean isInSOAPHeader(XMLSecEvent xmlSecEvent) {
        final List<QName> elementPath = xmlSecEvent.getElementPath();
        return isInSOAPHeader(elementPath);
    }

    public static boolean isInSOAPHeader(List<QName> elementPath) {
        if (elementPath.size() > 1) {
            final QName secondLevelElementName = elementPath.get(1);
            return WSSConstants.TAG_soap_Header_LocalName.equals(secondLevelElementName.getLocalPart())
                    && elementPath.get(0).getNamespaceURI().equals(secondLevelElementName.getNamespaceURI());
        }
        return false;
    }

    public static boolean isInSOAPBody(XMLSecEvent xmlSecEvent) {
        final List<QName> elementPath = xmlSecEvent.getElementPath();
        return isInSOAPBody(elementPath);
    }

    public static boolean isInSOAPBody(List<QName> elementPath) {
        if (elementPath.size() > 1) {
            final QName secondLevelElementName = elementPath.get(1);
            return WSSConstants.TAG_soap_Body_LocalName.equals(secondLevelElementName.getLocalPart())
                    && elementPath.get(0).getNamespaceURI().equals(secondLevelElementName.getNamespaceURI());
        }
        return false;
    }

    public static boolean isInSecurityHeader(XMLSecEvent xmlSecEvent, String actorOrRole) {
        final List<QName> elementPath = xmlSecEvent.getElementPath();
        return isInSecurityHeader(xmlSecEvent, elementPath, actorOrRole);
    }

    public static boolean isInSecurityHeader(XMLSecEvent xmlSecEvent, List<QName> elementPath, String actorOrRole) {
        if (elementPath.size() > 2) {
            final QName secondLevelElementName = elementPath.get(1);
            return WSSConstants.TAG_wsse_Security.equals(elementPath.get(2))
                    && isResponsibleActorOrRole(xmlSecEvent.getStartElementAtLevel(3), actorOrRole)
                    && WSSConstants.TAG_soap_Header_LocalName.equals(secondLevelElementName.getLocalPart())
                    && elementPath.get(0).getNamespaceURI().equals(secondLevelElementName.getNamespaceURI());
        }
        return false;
    }

    public static boolean isSecurityHeaderElement(XMLSecEvent xmlSecEvent, String actorOrRole) {
        if (!xmlSecEvent.isStartElement()) {
            return false;
        }

        final List<QName> elementPath = xmlSecEvent.getElementPath();
        if (elementPath.size() == 3) {
            final QName secondLevelElementName = elementPath.get(1);
            return WSSConstants.TAG_wsse_Security.equals(elementPath.get(2))
                    && isResponsibleActorOrRole(xmlSecEvent.getStartElementAtLevel(3), actorOrRole)
                    && WSSConstants.TAG_soap_Header_LocalName.equals(secondLevelElementName.getLocalPart())
                    && elementPath.get(0).getNamespaceURI().equals(secondLevelElementName.getNamespaceURI());
        }
        return false;
    }

    public static void updateSecurityHeaderOrder(
            OutputProcessorChain outputProcessorChain, QName headerElementName,
            XMLSecurityConstants.Action action, boolean onTop) {

        final OutboundSecurityContext securityContext = outputProcessorChain.getSecurityContext();

        Map<Object, SecurePart> dynamicSecureParts = securityContext.getAsMap(WSSConstants.ENCRYPTION_PARTS);
        boolean encrypted = dynamicSecureParts.containsKey(headerElementName);

        List<SecurityHeaderOrder> securityHeaderOrderList = securityContext.getAsList(SecurityHeaderOrder.class);
        if (securityHeaderOrderList == null) {
            securityContext.putList(SecurityHeaderOrder.class, Collections.<SecurityHeaderOrder>emptyList());
            securityHeaderOrderList = securityContext.getAsList(SecurityHeaderOrder.class);
        }
        if (onTop) {
            securityHeaderOrderList.add(0, new SecurityHeaderOrder(headerElementName, action, encrypted));
        } else {
            securityHeaderOrderList.add(new SecurityHeaderOrder(headerElementName, action, encrypted));
        }
    }

    public static boolean isResponsibleActorOrRole(XMLSecStartElement xmlSecStartElement, String responsibleActor) {
        final QName actorRole;
        final String soapVersionNamespace = getSOAPMessageVersionNamespace(xmlSecStartElement);
        if (WSSConstants.NS_SOAP11.equals(soapVersionNamespace)) {
            actorRole = WSSConstants.ATT_soap11_Actor;
        } else {
            actorRole = WSSConstants.ATT_soap12_Role;
        }

        String actor = null;
        Attribute attribute = xmlSecStartElement.getAttributeByName(actorRole);
        if (attribute != null) {
            actor = attribute.getValue();
        }

        if (responsibleActor == null) {
            return actor == null;
        } else {
            return responsibleActor.equals(actor);
        }
    }

    public static void createBinarySecurityTokenStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                          OutputProcessorChain outputProcessorChain,
                                                          String referenceId, X509Certificate[] x509Certificates,
                                                          boolean useSingleCertificate)
            throws XMLStreamException, XMLSecurityException {
        String valueType;
        if (useSingleCertificate) {
            valueType = WSSConstants.NS_X509_V3_TYPE;
        } else {
            valueType = WSSConstants.NS_X509PKIPathv1;
        }
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(3);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, valueType));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_wsu_Id, referenceId));
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken, false, attributes);
        try {
            if (useSingleCertificate) {
                abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
            } else {
                try {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
                    List<X509Certificate> certificates = Arrays.asList(x509Certificates);
                    abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(certificateFactory.generateCertPath(certificates).getEncoded()));
                } catch (CertificateException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                } catch (NoSuchProviderException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                }
            }
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken);
    }

    public static void createX509SubjectKeyIdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                               OutputProcessorChain outputProcessorChain,
                                                               X509Certificate[] x509Certificates)
            throws XMLSecurityException, XMLStreamException {
        // As per the 1.1 specification, SKI can only be used for a V3 certificate
        if (x509Certificates[0].getVersion() != 3) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidCertForSKI");
        }

        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_X509SubjectKeyIdentifier));
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        byte data[] = new Merlin().getSKIBytesFromCert(x509Certificates[0]);
        abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    public static void createX509KeyIdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                        OutputProcessorChain outputProcessorChain,
                                                        X509Certificate[] x509Certificates)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_X509_V3_TYPE));
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        try {
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    public static void createThumbprintKeyIdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                              OutputProcessorChain outputProcessorChain,
                                                              X509Certificate[] x509Certificates)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_THUMBPRINT));
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] data = sha.digest(x509Certificates[0].getEncoded());
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    public static void createEncryptedKeySha1IdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                                 OutputProcessorChain outputProcessorChain, Key key)
            throws XMLStreamException, XMLSecurityException {

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] data = sha.digest(key.getEncoded());
            createEncryptedKeySha1IdentifierStructure(abstractOutputProcessor, outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }
    
    public static void createEncryptedKeySha1IdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                                 OutputProcessorChain outputProcessorChain, String identifier)
            throws XMLStreamException, XMLSecurityException {

        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_ENCRYPTED_KEY_SHA1));
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, identifier);
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }
    
    public static void createKerberosSha1IdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                                 OutputProcessorChain outputProcessorChain, String identifier)
            throws XMLStreamException, XMLSecurityException {

        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_Kerberos5_AP_REQ_SHA1));
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, identifier);
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    public static void createBSTReferenceStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                   OutputProcessorChain outputProcessorChain, String referenceId,
                                                   String valueType, boolean includedInMessage)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        String uri = includedInMessage ? "#" + referenceId : referenceId;
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_URI, uri));
        if (valueType != null) {
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, valueType));
        }
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, false, attributes);
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
    }

    public static void createEmbeddedKeyIdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                            OutputProcessorChain outputProcessorChain,
                                                            WSSecurityTokenConstants.TokenType tokenType, String referenceId)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
        if (WSSecurityTokenConstants.Saml10Token.equals(tokenType) || WSSecurityTokenConstants.Saml11Token.equals(tokenType)) {
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML10_TYPE));
        } else if (WSSecurityTokenConstants.Saml20Token.equals(tokenType)) {
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML20_TYPE));
        }
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, referenceId);
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }
    
    public static void createSAMLKeyIdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                            OutputProcessorChain outputProcessorChain,
                                                            WSSecurityTokenConstants.TokenType tokenType, String referenceId)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
        if (WSSecurityTokenConstants.Saml10Token.equals(tokenType) || WSSecurityTokenConstants.Saml11Token.equals(tokenType)) {
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML10_TYPE));
        } else if (WSSecurityTokenConstants.Saml20Token.equals(tokenType)) {
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML20_TYPE));
        }
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, referenceId);
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    public static void createUsernameTokenReferenceStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                             OutputProcessorChain outputProcessorChain, String tokenId)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_URI, "#" + tokenId));
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_USERNAMETOKEN_PROFILE_UsernameToken));
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, false, attributes);
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
    }

    public static void createReferenceListStructureForEncryption(AbstractOutputProcessor abstractOutputProcessor,
                                                             OutputProcessorChain outputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        List<EncryptionPartDef> encryptionPartDefs =
                outputProcessorChain.getSecurityContext().getAsList(EncryptionPartDef.class);
        if (encryptionPartDefs == null) {
            return;
        }
        List<XMLSecAttribute> attributes;
        abstractOutputProcessor.createStartElementAndOutputAsEvent(
                outputProcessorChain, XMLSecurityConstants.TAG_xenc_ReferenceList, true, null);
        //output the references to the encrypted data:
        Iterator<EncryptionPartDef> encryptionPartDefIterator = encryptionPartDefs.iterator();
        while (encryptionPartDefIterator.hasNext()) {
            EncryptionPartDef encryptionPartDef = encryptionPartDefIterator.next();

            attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(abstractOutputProcessor.createAttribute(
                    XMLSecurityConstants.ATT_NULL_URI, "#" + encryptionPartDef.getEncRefId()));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(
                    outputProcessorChain, XMLSecurityConstants.TAG_xenc_DataReference, false, attributes);
            final String compressionAlgorithm =
                    ((WSSSecurityProperties)abstractOutputProcessor.getSecurityProperties()).getEncryptionCompressionAlgorithm();
            if (compressionAlgorithm != null) {
                abstractOutputProcessor.createStartElementAndOutputAsEvent(
                        outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms, true, null);
                attributes = new ArrayList<XMLSecAttribute>(1);
                attributes.add(abstractOutputProcessor.createAttribute(
                        XMLSecurityConstants.ATT_NULL_Algorithm, compressionAlgorithm));
                abstractOutputProcessor.createStartElementAndOutputAsEvent(
                        outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform, false, attributes);
                abstractOutputProcessor.createEndElementAndOutputAsEvent(
                        outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform);
                abstractOutputProcessor.createEndElementAndOutputAsEvent(
                        outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms);
            }
            abstractOutputProcessor.createEndElementAndOutputAsEvent(
                    outputProcessorChain, XMLSecurityConstants.TAG_xenc_DataReference);
        }
        abstractOutputProcessor.createEndElementAndOutputAsEvent(
                outputProcessorChain, XMLSecurityConstants.TAG_xenc_ReferenceList);
    }

    public static void createEncryptedDataStructureForAttachments(
            AbstractOutputProcessor abstractOutputProcessor, OutputProcessorChain outputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        
        List<EncryptionPartDef> encryptionPartDefs =
                outputProcessorChain.getSecurityContext().getAsList(EncryptionPartDef.class);
        if (encryptionPartDefs == null) {
            return;
        }

        Iterator<EncryptionPartDef> encryptionPartDefIterator = encryptionPartDefs.iterator();
        while (encryptionPartDefIterator.hasNext()) {
            EncryptionPartDef encryptionPartDef = encryptionPartDefIterator.next();

            if (encryptionPartDef.getCipherReferenceId() == null) {
                continue;
            }

            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(3);
            attributes.add(abstractOutputProcessor.createAttribute(XMLSecurityConstants.ATT_NULL_Id,
                    encryptionPartDef.getEncRefId()));
            if (encryptionPartDef.getModifier() == SecurePart.Modifier.Element) {
                attributes.add(
                        abstractOutputProcessor.createAttribute(XMLSecurityConstants.ATT_NULL_Type,
                                WSSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_COMPLETE));
            } else {
                attributes.add(
                        abstractOutputProcessor.createAttribute(XMLSecurityConstants.ATT_NULL_Type,
                                WSSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_CONTENT_ONLY));
            }
            attributes.add(
                    abstractOutputProcessor.createAttribute(XMLSecurityConstants.ATT_NULL_MimeType,
                            encryptionPartDef.getMimeType()));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_EncryptedData, true, attributes);

            attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(abstractOutputProcessor.createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm,
                    abstractOutputProcessor.getSecurityProperties().getEncryptionSymAlgorithm()));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_EncryptionMethod, false, attributes);

            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_EncryptionMethod);

            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_dsig_KeyInfo, true, null);

            attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_wsse11_TokenType,
                    WSSConstants.NS_WSS_ENC_KEY_VALUE_TYPE));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain,
                    WSSConstants.TAG_wsse_SecurityTokenReference, true, attributes);

            attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_URI,
                    "#" + encryptionPartDef.getKeyId()));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain,
                    WSSConstants.TAG_wsse_Reference, false, attributes);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain,
                    WSSConstants.TAG_wsse_Reference);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain,
                    WSSConstants.TAG_wsse_SecurityTokenReference);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_dsig_KeyInfo);

            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_CipherData, false, null);

            attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_URI,
                    "cid:" + encryptionPartDef.getCipherReferenceId()));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_CipherReference, false, attributes);

            abstractOutputProcessor.createStartElementAndOutputAsEvent(
                    outputProcessorChain, XMLSecurityConstants.TAG_xenc_Transforms, false, null);

            attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(abstractOutputProcessor.createAttribute(
                    XMLSecurityConstants.ATT_NULL_Algorithm, WSSConstants.SWA_ATTACHMENT_CIPHERTEXT_TRANS));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(
                    outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform, true, attributes);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(
                    outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(
                    outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms);

            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_CipherReference);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_CipherData);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain,
                    XMLSecurityConstants.TAG_xenc_EncryptedData);
        }
    }

    @SuppressWarnings("unchecked")
    public static TokenSecurityEvent<? extends InboundSecurityToken> 
        createTokenSecurityEvent(final InboundSecurityToken inboundSecurityToken, String correlationID) throws WSSecurityException {
        WSSecurityTokenConstants.TokenType tokenType = inboundSecurityToken.getTokenType();

        TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent;
        if (WSSecurityTokenConstants.X509V1Token.equals(tokenType) ||
                WSSecurityTokenConstants.X509V3Token.equals(tokenType) ||
                WSSecurityTokenConstants.X509Pkcs7Token.equals(tokenType) ||
                WSSecurityTokenConstants.X509PkiPathV1Token.equals(tokenType)) {
            tokenSecurityEvent = new X509TokenSecurityEvent();
        } else if (WSSecurityTokenConstants.UsernameToken.equals(tokenType)) {
            tokenSecurityEvent = new UsernameTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.KerberosToken.equals(tokenType)) {
            tokenSecurityEvent = new KerberosTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.SecurityContextToken.equals(tokenType)) {
            tokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.Saml10Token.equals(tokenType) ||
                WSSecurityTokenConstants.Saml11Token.equals(tokenType) ||
                WSSecurityTokenConstants.Saml20Token.equals(tokenType)) {
            tokenSecurityEvent = new SamlTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.RelToken.equals(tokenType)) {
            tokenSecurityEvent = new RelTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.HttpsToken.equals(tokenType)) {
            tokenSecurityEvent = new HttpsTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.KeyValueToken.equals(tokenType)) {
            tokenSecurityEvent = new KeyValueTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.DerivedKeyToken.equals(tokenType)) {
            tokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        } else if (WSSecurityTokenConstants.EncryptedKeyToken.equals(tokenType)) {
            tokenSecurityEvent = new EncryptedKeyTokenSecurityEvent();
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN);
        }
        ((TokenSecurityEvent<SecurityToken>)tokenSecurityEvent).setSecurityToken(inboundSecurityToken);
        tokenSecurityEvent.setCorrelationID(correlationID);
        return (TokenSecurityEvent<? extends InboundSecurityToken>)tokenSecurityEvent;
    }

    public static boolean pathMatches(List<QName> path1, List<QName> path2, boolean matchAnySoapNS, boolean lastElementWildCard) {
        if (path1 == null) {
            throw new IllegalArgumentException("Internal error");
        }
        if (path2 == null || path1.size() != path2.size()) {
            return false;
        }
        Iterator<QName> path1Iterator = path1.iterator();
        Iterator<QName> path2Iterator = path2.iterator();
        while (path1Iterator.hasNext()) {
            QName qName1 = path1Iterator.next();
            QName qName2 = path2Iterator.next();
            if (matchAnySoapNS && (WSSConstants.NS_SOAP11.equals(qName1.getNamespaceURI())
                    || WSSConstants.NS_SOAP12.equals(qName1.getNamespaceURI()))) {
                if (!qName1.getLocalPart().equals(qName2.getLocalPart())) {
                    return false;
                }
            } else if (!qName1.equals(qName2)) {
                if (!path1Iterator.hasNext() && lastElementWildCard) {
                    if (!qName1.getNamespaceURI().equals(qName2.getNamespaceURI())) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
        return true;
    }

    public static String pathAsString(List<QName> path) {
        StringBuilder stringBuilder = new StringBuilder();
        Iterator<QName> pathIterator = path.iterator();
        while (pathIterator.hasNext()) {
            QName qName = pathIterator.next();
            stringBuilder.append('/');
            stringBuilder.append(qName.toString());
        }
        return stringBuilder.toString();
    }

    @SuppressWarnings("unchecked")
    public static <T extends SecurityToken> T getRootToken(T securityToken) throws XMLSecurityException {
        T tmp = securityToken;
        while (tmp.getKeyWrappingToken() != null) {
            tmp = (T)tmp.getKeyWrappingToken();
        }
        return tmp;
    }
    
    public static Schema loadWSSecuritySchemas() throws SAXException {
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        schemaFactory.setResourceResolver(new LSResourceResolver() {
            @Override
            public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
                if ("http://www.w3.org/2001/XMLSchema.dtd".equals(systemId)) {
                    ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                    concreteLSInput.setByteStream(ClassLoaderUtils.getResourceAsStream("schemas/XMLSchema.dtd", WSSec.class));
                    return concreteLSInput;
                } else if ("XMLSchema.dtd".equals(systemId)) {
                    ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                    concreteLSInput.setByteStream(ClassLoaderUtils.getResourceAsStream("schemas/XMLSchema.dtd", WSSec.class));
                    return concreteLSInput;
                } else if ("datatypes.dtd".equals(systemId)) {
                    ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                    concreteLSInput.setByteStream(ClassLoaderUtils.getResourceAsStream("schemas/datatypes.dtd", WSSec.class));
                    return concreteLSInput;
                } else if ("http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd".equals(systemId)) {
                    ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                    concreteLSInput.setByteStream(ClassLoaderUtils.getResourceAsStream("schemas/xmldsig-core-schema.xsd", WSSec.class));
                    return concreteLSInput;
                } else if ("http://www.w3.org/2001/xml.xsd".equals(systemId)) {
                    ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                    concreteLSInput.setByteStream(ClassLoaderUtils.getResourceAsStream("schemas/xml.xsd", WSSec.class));
                    return concreteLSInput;
                }
                return null;
            }
        });
        
        Schema schema = schemaFactory.newSchema(
                new Source[]{
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/exc-c14n.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/xmldsig-core-schema.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/xenc-schema.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/xenc-schema-11.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/xmldsig11-schema.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/oasis-200401-wss-wssecurity-utility-1.0.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/oasis-200401-wss-wssecurity-secext-1.0.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/oasis-wss-wssecurity-secext-1.1.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/ws-secureconversation-200502.xsd", WSSec.class)),
                        new StreamSource(ClassLoaderUtils.getResourceAsStream("schemas/ws-secureconversation-1.3.xsd", WSSec.class)),
                }
        );
        return schema;
    }
}
