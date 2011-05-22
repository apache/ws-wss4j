/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.ext;

import com.sun.istack.Nullable;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.crypto.Merlin;
import org.swssf.impl.EncryptionPartDef;
import org.swssf.impl.util.RFC2253Parser;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * An abstract OutputProcessor class for reusabilty
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public abstract class AbstractOutputProcessor implements OutputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected static final XMLEventFactory xmlEventFactory = XMLEventFactory.newFactory();
    protected SecurityProperties securityProperties;
    protected Constants.Action action;

    private Constants.Phase phase = Constants.Phase.PROCESSING;
    private Set<Object> beforeProcessors = new HashSet<Object>();
    private Set<Object> afterProcessors = new HashSet<Object>();

    protected AbstractOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        this.securityProperties = securityProperties;
        this.action = action;
    }

    public Constants.Phase getPhase() {
        return phase;
    }

    public void setPhase(Constants.Phase phase) {
        this.phase = phase;
    }

    public Set<Object> getBeforeProcessors() {
        return beforeProcessors;
    }

    public Set<Object> getAfterProcessors() {
        return afterProcessors;
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public Constants.Action getAction() {
        return action;
    }

    public abstract void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException;

    public void processNextEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        processEvent(xmlEvent, outputProcessorChain);
    }

    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.doFinal();
    }

    //todo copy attributes
    protected XMLEventNS cloneStartElementEvent(XMLEvent xmlEvent, List<Attribute> attributeList) throws XMLStreamException {
        XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;
        if (!xmlEvent.isStartElement()) {
            return xmlEventNS;
        }

        List<ComparableNamespace>[] xmlEventNSNamespaces = xmlEventNS.getNamespaceList();
        List<ComparableAttribute>[] xmlEventNsAttributes = xmlEventNS.getAttributeList();

        List<ComparableNamespace> currentXmlEventNamespaces = xmlEventNSNamespaces[0];
        currentXmlEventNamespaces.add(new ComparableNamespace(xmlEvent.asStartElement().getName().getPrefix(), xmlEvent.asStartElement().getName().getNamespaceURI()));

        List<Namespace> namespaceList = new ArrayList<Namespace>();
        @SuppressWarnings("unchecked")
        Iterator<Namespace> namespaceIterator = xmlEvent.asStartElement().getNamespaces();
        while (namespaceIterator.hasNext()) {
            Namespace namespace = namespaceIterator.next();
            namespaceList.add(createNamespace(namespace.getPrefix(), namespace.getNamespaceURI()));
        }

        for (int i = 0; i < attributeList.size(); i++) {
            Attribute attribute = attributeList.get(i);
            boolean found = false;
            for (int j = 0; j < namespaceList.size(); j++) {
                Namespace namespace = namespaceList.get(j);
                if (namespace.getPrefix() != null && attribute.getName().getPrefix() != null && namespace.getPrefix().equals(attribute.getName().getPrefix())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                namespaceList.add(createNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
                currentXmlEventNamespaces.add(new ComparableNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
            }
        }

        StartElement startElement = xmlEventFactory.createStartElement(xmlEvent.asStartElement().getName(), attributeList.iterator(), namespaceList.iterator());

        return new XMLEventNS(startElement, xmlEventNSNamespaces, xmlEventNsAttributes);
    }

    protected void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, Map<QName, String> namespaces, Map<QName, String> attributes) throws XMLStreamException, WSSecurityException {
        List<Attribute> attributeList = new LinkedList<Attribute>();
        if (attributes != null) {
            Iterator<Map.Entry<QName, String>> attributeIterator = attributes.entrySet().iterator();
            while (attributeIterator.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = attributeIterator.next();
                Attribute attribute = xmlEventFactory.createAttribute(qNameStringEntry.getKey(), qNameStringEntry.getValue());
                attributeList.add(attribute);
            }
        }
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        if (namespaces != null) {
            Iterator<Map.Entry<QName, String>> namespaceIterator = namespaces.entrySet().iterator();
            while (namespaceIterator.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = namespaceIterator.next();
                namespaceList.add(xmlEventFactory.createNamespace(qNameStringEntry.getKey().getLocalPart(), qNameStringEntry.getValue()));
            }
        }
        StartElement startElement = xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator());
        outputAsEvent(outputProcessorChain, startElement);
    }

    protected void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, @Nullable Map<QName, String> attributes) throws XMLStreamException, WSSecurityException {
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        namespaceList.add(xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI()));

        List<Attribute> attributeList = new LinkedList<Attribute>();
        if (attributes != null) {
            Iterator<Map.Entry<QName, String>> attributeIterator = attributes.entrySet().iterator();
            while (attributeIterator.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = attributeIterator.next();
                Attribute attribute = xmlEventFactory.createAttribute(qNameStringEntry.getKey(), qNameStringEntry.getValue());
                attributeList.add(attribute);

                if ("".equals(attribute.getName().getPrefix())) {
                    continue;
                }

                boolean found = false;
                for (int i = 0; i < namespaceList.size(); i++) {
                    Namespace namespace = namespaceList.get(i);
                    if (namespace.getPrefix() != null && attribute.getName().getPrefix() != null && namespace.getPrefix().equals(attribute.getName().getPrefix())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    namespaceList.add(xmlEventFactory.createNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
                }
            }
        }

        StartElement startElement = xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator());
        outputAsEvent(outputProcessorChain, startElement);
    }

    protected EndElement createEndElement(QName element) {
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        namespaceList.add(xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI()));
        return xmlEventFactory.createEndElement(element, namespaceList.iterator());
    }

    protected void createEndElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element) throws XMLStreamException, WSSecurityException {
        outputAsEvent(outputProcessorChain, createEndElement(element));
    }

    protected void createCharactersAndOutputAsEvent(OutputProcessorChain outputProcessorChain, String characters) throws XMLStreamException, WSSecurityException {
        outputAsEvent(outputProcessorChain, createCharacters(characters));
    }

    protected Characters createCharacters(String characters) {
        return xmlEventFactory.createCharacters(characters);
    }

    protected Attribute createAttribute(QName attribute, String attributeValue) {
        return xmlEventFactory.createAttribute(attribute, attributeValue);
    }

    protected Namespace createNamespace(String prefix, String uri) {
        return xmlEventFactory.createNamespace(prefix, uri);
    }

    protected void outputAsEvent(OutputProcessorChain outputProcessorChain, XMLEvent xmlEvent) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(xmlEvent);
    }

    protected void createSecurityTokenReferenceStructureForSignature(
            OutputProcessorChain outputProcessorChain,
            SecurityToken securityToken,
            Constants.KeyIdentifierType keyIdentifierType,
            boolean useSingleCertificate)
            throws XMLStreamException, WSSecurityException {

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_wsu_Id, "STRId-" + UUID.randomUUID().toString());
        if ((keyIdentifierType == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE
                || keyIdentifierType == Constants.KeyIdentifierType.BST_EMBEDDED)
                && !useSingleCertificate) {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_X509PKIPathv1);
        } else if (securityToken.getKeyIdentifierType() == Constants.KeyIdentifierType.SAML_10) {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_SAML11_TOKEN_PROFILE_TYPE);
        } else if (securityToken.getKeyIdentifierType() == Constants.KeyIdentifierType.SAML_20) {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_SAML20_TOKEN_PROFILE_TYPE);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, attributes);

        X509Certificate[] x509Certificates = securityToken.getX509Certificates();
        String tokenId = securityToken.getId();

        if (keyIdentifierType == Constants.KeyIdentifierType.ISSUER_SERIAL) {
            createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
            createX509SubjectKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
            createX509KeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
            createThumbprintKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.BST_EMBEDDED) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, true);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, false);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.EMBEDDED_SECURITY_TOKEN_REF) {
            createEmbeddedSecurityTokenReferenceStructure(outputProcessorChain, tokenId);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.EMEDDED_KEYIDENTIFIER_REF) {
            createEmbeddedKeyIdentifierStructure(outputProcessorChain, securityToken.getKeyIdentifierType(), tokenId);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.USERNAMETOKEN_SIGNED) {
            createUsernameTokenReferenceStructure(outputProcessorChain, tokenId);
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "unsupportedSecurityToken", keyIdentifierType.name());
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
    }

    protected void createSecurityTokenReferenceStructureForEncryptedKey(
            OutputProcessorChain outputProcessorChain,
            SecurityToken securityToken,
            Constants.KeyIdentifierType keyIdentifierType,
            boolean useSingleCertificate)
            throws XMLStreamException, WSSecurityException {

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_wsu_Id, "STRId-" + UUID.randomUUID().toString());
        if ((keyIdentifierType == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE
                || keyIdentifierType == Constants.KeyIdentifierType.BST_EMBEDDED)
                && !useSingleCertificate) {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_X509PKIPathv1);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, attributes);

        X509Certificate[] x509Certificates = securityToken.getKeyWrappingToken().getX509Certificates();
        String tokenId = securityToken.getKeyWrappingToken().getId();

        if (keyIdentifierType == Constants.KeyIdentifierType.ISSUER_SERIAL) {
            createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
            createX509SubjectKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
            createX509KeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
            createThumbprintKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.BST_EMBEDDED) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, true);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, false);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.EMBEDDED_SECURITY_TOKEN_REF) {
            createEmbeddedSecurityTokenReferenceStructure(outputProcessorChain, tokenId);
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "unsupportedSecurityToken", keyIdentifierType.name());
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
    }

    protected void createSecurityTokenReferenceStructureForDerivedKey(
            OutputProcessorChain outputProcessorChain,
            SecurityToken securityToken,
            Constants.KeyIdentifierType keyIdentifierType,
            Constants.DerivedKeyTokenReference derivedKeyTokenReference,
            boolean useSingleCertificate)
            throws XMLStreamException, WSSecurityException {

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_wsu_Id, "STRId-" + UUID.randomUUID().toString());
        if ((keyIdentifierType == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE
                || keyIdentifierType == Constants.KeyIdentifierType.BST_EMBEDDED)
                && !useSingleCertificate) {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_X509PKIPathv1);
        } else if (derivedKeyTokenReference == Constants.DerivedKeyTokenReference.EncryptedKey) {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_WSS_ENC_KEY_VALUE_TYPE);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, attributes);

        X509Certificate[] x509Certificates = securityToken.getKeyWrappingToken().getX509Certificates();
        String tokenId = securityToken.getKeyWrappingToken().getId();

        if (keyIdentifierType == Constants.KeyIdentifierType.ISSUER_SERIAL) {
            createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
            createX509SubjectKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
            createX509KeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
            createThumbprintKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.BST_EMBEDDED) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, true);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, false);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.EMBEDDED_SECURITY_TOKEN_REF) {
            createEmbeddedSecurityTokenReferenceStructure(outputProcessorChain, tokenId);
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "unsupportedSecurityToken", keyIdentifierType.name());
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
    }

    protected void createUsernameTokenReferenceStructure(OutputProcessorChain outputProcessorChain, String tokenId) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_URI, "#" + tokenId);
        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_USERNAMETOKEN_PROFILE_UsernameToken);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference, attributes);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference);
    }

    protected void createEmbeddedSecurityTokenReferenceStructure(OutputProcessorChain outputProcessorChain, String referenceId) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_URI, "#" + referenceId);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference, attributes);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference);
    }

    protected void createEmbeddedKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, Constants.KeyIdentifierType keyIdentifierType, String referenceId) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        if (keyIdentifierType == Constants.KeyIdentifierType.SAML_10) {
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_SAML10_TYPE);
        } else if (keyIdentifierType == Constants.KeyIdentifierType.SAML_20) {
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_SAML20_TYPE);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
        createCharactersAndOutputAsEvent(outputProcessorChain, referenceId);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
    }

    protected void createBSTReferenceStructure(OutputProcessorChain outputProcessorChain, String referenceId, X509Certificate[] x509Certificates, boolean useSingleCertificate, boolean embed) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        String valueType;
        if (useSingleCertificate) {
            valueType = Constants.NS_X509_V3_TYPE;
        } else {
            valueType = Constants.NS_X509PKIPathv1;
        }
        attributes.put(Constants.ATT_NULL_URI, "#" + referenceId);
        attributes.put(Constants.ATT_NULL_ValueType, valueType);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference, attributes);
        if (embed) {
            createBinarySecurityTokenStructure(outputProcessorChain, referenceId, x509Certificates, useSingleCertificate);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference);
    }

    protected void createBinarySecurityTokenStructure(OutputProcessorChain outputProcessorChain, String referenceId, X509Certificate[] x509Certificates, boolean useSingleCertificate) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        String valueType;
        if (useSingleCertificate) {
            valueType = Constants.NS_X509_V3_TYPE;
        } else {
            valueType = Constants.NS_X509PKIPathv1;
        }
        attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(Constants.ATT_NULL_ValueType, valueType);
        attributes.put(Constants.ATT_wsu_Id, referenceId);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
        try {
            if (useSingleCertificate) {
                createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
            } else {
                try {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
                    List<X509Certificate> certificates = Arrays.asList(x509Certificates);
                    createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(certificateFactory.generateCertPath(certificates).getEncoded()));
                } catch (CertificateException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                } catch (NoSuchProviderException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                }
            }
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
    }

    protected void createThumbprintKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_THUMBPRINT);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
        try {
            MessageDigest sha;
            sha = MessageDigest.getInstance("SHA-1");
            sha.reset();
            sha.update(x509Certificates[0].getEncoded());
            byte[] data = sha.digest();

            createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
    }

    protected void createX509KeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
        try {
            createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
    }

    protected void createX509SubjectKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws WSSecurityException, XMLStreamException {
        // As per the 1.1 specification, SKI can only be used for a V3 certificate
        if (x509Certificates[0].getVersion() != 3) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "invalidCertForSKI");
        }

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509SubjectKeyIdentifier);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
        byte data[] = new Merlin().getSKIBytesFromCert(x509Certificates[0]);
        createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
    }

    protected void createX509IssuerSerialStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, WSSecurityException {
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509Data, null);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509IssuerSerial, null);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509IssuerName, null);
        createCharactersAndOutputAsEvent(outputProcessorChain, RFC2253Parser.normalize(x509Certificates[0].getIssuerDN().getName(), true));
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509IssuerName);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509SerialNumber, null);
        createCharactersAndOutputAsEvent(outputProcessorChain, x509Certificates[0].getSerialNumber().toString());
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509SerialNumber);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509IssuerSerial);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_X509Data);
    }

    protected void createReferenceListStructure(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        List<EncryptionPartDef> encryptionPartDefs = outputProcessorChain.getSecurityContext().getAsList(EncryptionPartDef.class);
        if (encryptionPartDefs == null) {
            return;
        }
        Map<QName, String> attributes;
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_ReferenceList, null);
        //output the references to the encrypted data:
        Iterator<EncryptionPartDef> encryptionPartDefIterator = encryptionPartDefs.iterator();
        while (encryptionPartDefIterator.hasNext()) {
            EncryptionPartDef encryptionPartDef = encryptionPartDefIterator.next();

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + encryptionPartDef.getEncRefId());
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_DataReference, attributes);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_DataReference);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_ReferenceList);
    }
}
