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
package org.swssf.wss.ext;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.stax.crypto.Merlin;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.algorithms.ECDSAUtils;
import org.swssf.wss.securityEvent.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSUtils extends XMLSecurityUtils {

    protected WSSUtils() {
        super();
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
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSHA1availabe", e);
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
            return (WSSConstants.TAG_soap_Header_LocalName.equals(secondLevelElementName.getLocalPart())
                    && elementPath.get(0).getNamespaceURI().equals(secondLevelElementName.getNamespaceURI()));
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
            return (WSSConstants.TAG_soap_Body_LocalName.equals(secondLevelElementName.getLocalPart())
                    && elementPath.get(0).getNamespaceURI().equals(secondLevelElementName.getNamespaceURI()));
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

    public static boolean isResponsibleActorOrRole(XMLSecStartElement xmlSecStartElement, String responsibleActor) {
        final QName actorRole;
        final String soapVersionNamespace = getSOAPMessageVersionNamespace(xmlSecStartElement);
        if (WSSConstants.NS_SOAP11.equals(soapVersionNamespace)) {
            actorRole = WSSConstants.ATT_soap11_Actor;
        } else {
            actorRole = WSSConstants.ATT_soap12_Role;
        }

        String actor = null;
        @SuppressWarnings("unchecked")
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
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                } catch (NoSuchProviderException e) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                }
            }
        } catch (CertificateEncodingException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken);
    }

    public static void createX509SubjectKeyIdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                               OutputProcessorChain outputProcessorChain,
                                                               X509Certificate[] x509Certificates)
            throws XMLSecurityException, XMLStreamException {
        // As per the 1.1 specification, SKI can only be used for a V3 certificate
        if (x509Certificates[0].getVersion() != 3) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, "invalidCertForSKI");
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
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
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
            MessageDigest sha;
            sha = MessageDigest.getInstance("SHA-1");
            sha.reset();
            sha.update(x509Certificates[0].getEncoded());
            byte[] data = sha.digest();

            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        } catch (CertificateEncodingException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    public static void createBSTReferenceStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                   OutputProcessorChain outputProcessorChain, String referenceId,
                                                   String valueType)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_URI, "#" + referenceId));
        if (valueType != null) {
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, valueType));
        }
        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, false, attributes);
        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
    }

    public static void createEmbeddedKeyIdentifierStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                            OutputProcessorChain outputProcessorChain,
                                                            XMLSecurityConstants.TokenType tokenType, String referenceId)
            throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
        if (tokenType.equals(WSSConstants.Saml10Token) || tokenType.equals(WSSConstants.Saml11Token)) {
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML10_TYPE));
        } else if (tokenType.equals(WSSConstants.Saml20Token)) {
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

    public static void createKeyValueTokenStructure(AbstractOutputProcessor abstractOutputProcessor,
                                                    OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates)
            throws XMLStreamException, XMLSecurityException {

        X509Certificate x509Certificate = x509Certificates[0];
        PublicKey publicKey = x509Certificate.getPublicKey();
        String algorithm = publicKey.getAlgorithm();

        abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_KeyValue, true, null);

        if ("RSA".equals(algorithm)) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_RSAKeyValue, false, null);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Modulus, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(rsaPublicKey.getModulus().toByteArray()));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Modulus);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Exponent, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(rsaPublicKey.getPublicExponent().toByteArray()));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Exponent);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_RSAKeyValue);
        } else if ("DSA".equals(algorithm)) {
            DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
            BigInteger j = dsaPublicKey.getParams().getP().subtract(BigInteger.ONE).divide(dsaPublicKey.getParams().getQ());
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_DSAKeyValue, false, null);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_P, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(dsaPublicKey.getParams().getP().toByteArray()));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_P);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Q, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(dsaPublicKey.getParams().getQ().toByteArray()));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Q);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_G, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(dsaPublicKey.getParams().getG().toByteArray()));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_G);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Y, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(dsaPublicKey.getY().toByteArray()));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_Y);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_J, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(j.toByteArray()));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_J);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_DSAKeyValue);
        } else if ("EC".equals(algorithm)) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(abstractOutputProcessor.createAttribute(WSSConstants.ATT_NULL_URI, "urn:oid:" + ECDSAUtils.getOIDFromPublicKey(ecPublicKey)));
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig11_ECKeyValue, true, null);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig11_NamedCurve, false, attributes);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig11_NamedCurve);
            abstractOutputProcessor.createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig11_PublicKey, false, null);
            abstractOutputProcessor.createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(ECDSAUtils.encodePoint(ecPublicKey.getW(), ecPublicKey.getParams().getCurve())));
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig11_PublicKey);
            abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig11_ECKeyValue);
        }

        abstractOutputProcessor.createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_KeyValue);
    }

    public static TokenSecurityEvent createTokenSecurityEvent(final SecurityToken securityToken) throws WSSecurityException {
        WSSConstants.TokenType tokenType = (WSSConstants.TokenType) securityToken.getTokenType();

        TokenSecurityEvent tokenSecurityEvent;
        if (tokenType == WSSConstants.X509V1Token
                || tokenType == WSSConstants.X509V3Token
                || tokenType == WSSConstants.X509Pkcs7Token
                || tokenType == WSSConstants.X509PkiPathV1Token) {
            tokenSecurityEvent = new X509TokenSecurityEvent();
        } else if (tokenType == WSSConstants.UsernameToken) {
            tokenSecurityEvent = new UsernameTokenSecurityEvent();
        } else if (tokenType == WSSConstants.KerberosToken) {
            tokenSecurityEvent = new KerberosTokenSecurityEvent();
        } else if (tokenType == WSSConstants.SpnegoContextToken) {
            tokenSecurityEvent = new SpnegoContextTokenSecurityEvent();
        } else if (tokenType == WSSConstants.SecurityContextToken) {
            tokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        } else if (tokenType == WSSConstants.SecureConversationToken) {
            tokenSecurityEvent = new SecureConversationTokenSecurityEvent();
        } else if (tokenType == WSSConstants.Saml10Token
                || tokenType == WSSConstants.Saml11Token
                || tokenType == WSSConstants.Saml20Token) {
            tokenSecurityEvent = new SamlTokenSecurityEvent();
        } else if (tokenType == WSSConstants.RelToken) {
            tokenSecurityEvent = new RelTokenSecurityEvent();
        } else if (tokenType == WSSConstants.HttpsToken) {
            tokenSecurityEvent = new HttpsTokenSecurityEvent();
        } else if (tokenType == WSSConstants.KeyValueToken) {
            tokenSecurityEvent = new KeyValueTokenSecurityEvent();
        } else if (tokenType == WSSConstants.DerivedKeyToken) {
            tokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        } else if (tokenType == WSSConstants.EncryptedKeyToken) {
            tokenSecurityEvent = new EncryptedKeyTokenSecurityEvent();
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN);
        }
        tokenSecurityEvent.setSecurityToken(securityToken);
        return tokenSecurityEvent;
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
}
