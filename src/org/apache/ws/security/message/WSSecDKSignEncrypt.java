/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.message;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import org.apache.axis.encoding.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.dkalgo.AlgoFactory;
import org.apache.ws.security.conversation.dkalgo.DerivationAlgorithm;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

/**
 * Encrypts and signes parts of a message with derived keys derived from a
 * symmetric key. This symmetric key will be included as an EncryptedKey
 * 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class WSSecDKSignEncrypt extends WSSecBase {

    private static Log log = LogFactory.getLog(WSSecEncrypt.class.getName());

    private static Log tlog = LogFactory.getLog("org.apache.ws.security.TIME");

    private Document document;
    
    protected String symEncAlgo = WSConstants.AES_128;

    protected String keyEncAlgo = WSConstants.KEYTRANSPORT_RSA15;
    
    protected String encrUser = null;
    
    private byte[] ephemeralKey;
    
    private byte[] derivedSigKey;
    
    private byte[] derivedEncrKey;

    private Element xencEncryptedKey;

    private String encKeyId = null;
    
    private BinarySecurity bstToken = null;

    private Element envelope;
    
    private DerivedKeyToken dkt = null;
    
    private String dkId = null;

    public Document build(Document doc, Crypto crypto, WSSecHeader secHeader) throws Exception  {
        
        /*
         * Setup the encrypted key
         */
        prepare(doc, crypto);
        
        /*
         * prepend elements in the right order to the security header
         */
        prependDKElementToHeader(secHeader);
        prependToHeader(secHeader);
        prependBSTElementToHeader(secHeader);
                
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);
        if (parts == null) {
            parts = new Vector();
            WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                    .getBodyQName().getLocalPart(), soapConstants
                    .getEnvelopeURI(), "Content");
            parts.add(encP);
        }
        Element externRefList = encryptForExternalRef(null, parts);
        addExternalRefElement(externRefList, secHeader);

        return document;
    }

    private Vector doEncryption(Document doc, byte[] secretKey,
            KeyInfo keyInfo, Vector references) throws Exception {

        SecretKey key = WSSecurityUtil.prepareSecretKey(this.symEncAlgo, secretKey);
        
        
        XMLCipher xmlCipher = null;
        try {
            String provider = wssConfig.getJceProviderId();
            if (provider == null) {
                xmlCipher = XMLCipher.getInstance(symEncAlgo);
            } else {
                xmlCipher = XMLCipher.getProviderInstance(symEncAlgo, provider);
            }
        } catch (XMLEncryptionException e3) {
            throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e3);
        }

        Vector encDataRefs = new Vector();

        for (int part = 0; part < references.size(); part++) {
            WSEncryptionPart encPart = (WSEncryptionPart) references.get(part);
            String elemName = encPart.getName();
            String nmSpace = encPart.getNamespace();
            String modifier = encPart.getEncModifier();
            /*
             * Third step: get the data to encrypt.
             */
            Element body = (Element) WSSecurityUtil.findElement(envelope,
                    elemName, nmSpace);
            if (body == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noEncElement", new Object[] { "{" + nmSpace + "}"
                                + elemName });
            }

            boolean content = modifier.equals("Content") ? true : false;
            String xencEncryptedDataId = "EncDataId-" + body.hashCode();

            /*
             * Forth step: encrypt data, and set neccessary attributes in
             * xenc:EncryptedData
             */
            try {
                xmlCipher.init(XMLCipher.ENCRYPT_MODE, key);
                EncryptedData encData = xmlCipher.getEncryptedData();
                encData.setId(xencEncryptedDataId);
                encData.setKeyInfo(keyInfo);
                xmlCipher.doFinal(doc, body, content);
            } catch (Exception e2) {
                throw new WSSecurityException(
                        WSSecurityException.FAILED_ENC_DEC, null, null, e2);
            }
            encDataRefs.add(new String("#" + xencEncryptedDataId));
        }
        return encDataRefs;
    }

    /**
     * @return
     */
    private byte[] generateNonce() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] temp = new byte[16];
        random.nextBytes(temp);
        return temp;
    }

    /**
     * Initialize a WSSec Derived key.
     * 
     * The method prepares and initializes a WSSec dereived key structure after the
     * relevant information was set. This method also creates and initializes the
     * derived token using the ephemeral key. After preparation references
     * can be added and encrypted.
     * 
     * </p>
     * 
     * This method does not add any element to the security header. This must be
     * done explicitly.
     * 
     * @param doc
     *            The unsigned SOAP envelope as <code>Document</code>
     * @param crypto
     *            An instance of the Crypto API to handle keystore and
     *            certificates
     * @throws WSSecurityException
     */

    public void prepare(Document doc, Crypto crypto)
        throws Exception {
        
        document = doc;
        
        /*
         * Set up the ephemeral key
         */
        this.ephemeralKey = getEphemeralKey();
        
        /*
         * Get the certificate that contains the public key for the public key
         * algorithm that will encrypt the generated symmetric (session) key.
         */
        X509Certificate remoteCert = null;

        X509Certificate[] certs = crypto.getCertificates(encrUser);
        if (certs == null || certs.length <= 0) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidX509Data", new Object[] { "for Encryption" });
        }
        remoteCert = certs[0];
        
        String certUri = "EncCertId-" + remoteCert.hashCode();
        Cipher cipher = WSSecurityUtil.getCipherInstance(keyEncAlgo, wssConfig
                .getJceProviderId());
        try {
            cipher.init(Cipher.ENCRYPT_MODE, remoteCert);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e);
        }
        
        if (doDebug) {
            log.debug("cipher blksize: " + cipher.getBlockSize()
                    + ", symm key length: " + this.ephemeralKey.length);
        }
        if (cipher.getBlockSize() < this.ephemeralKey.length) {
            throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "unsupportedKeyTransp",
                    new Object[] { "public key algorithm too weak to encrypt symmetric key" });
        }
        byte[] encryptedKey = null;
        try {
            encryptedKey = cipher.doFinal(this.ephemeralKey);
        } catch (IllegalStateException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e1);
        } catch (IllegalBlockSizeException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e1);
        } catch (BadPaddingException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e1);
        }
        Text keyText = WSSecurityUtil.createBase64EncodedTextNode(doc,
                encryptedKey);

        /*
         * Now we need to setup the EncryptedKey header block 1) create a
         * EncryptedKey element and set a wsu:Id for it 2) Generate ds:KeyInfo
         * element, this wraps the wsse:SecurityTokenReference 3) Create and set
         * up the SecurityTokenReference according to the keyIdentifer parameter
         * 4) Create the CipherValue element structure and insert the encrypted
         * session key
         */
        xencEncryptedKey = createEnrcyptedKey(doc, keyEncAlgo);
        encKeyId = "EncKeyId-" + xencEncryptedKey.hashCode();
        xencEncryptedKey.setAttributeNS(null, "Id", encKeyId);

        KeyInfo keyInfo = new KeyInfo(doc);

        SecurityTokenReference secToken = new SecurityTokenReference(doc);

        switch (keyIdentifierType) {
        case WSConstants.X509_KEY_IDENTIFIER:
            secToken.setKeyIdentifier(remoteCert);
            break;

        case WSConstants.SKI_KEY_IDENTIFIER:
            secToken.setKeyIdentifierSKI(remoteCert, crypto);
            break;

        case WSConstants.THUMBPRINT_IDENTIFIER:
            secToken.setKeyIdentifierThumb(remoteCert);
            break;

        case WSConstants.ISSUER_SERIAL:
            XMLX509IssuerSerial data = new XMLX509IssuerSerial(doc, remoteCert);
            X509Data x509Data = new X509Data(doc);
            x509Data.add(data);
            secToken.setX509IssuerSerial(x509Data);
            break;

        case WSConstants.BST_DIRECT_REFERENCE:
            Reference ref = new Reference(doc);
            ref.setURI("#" + certUri);
            bstToken = new X509Security(doc);
            ((X509Security) bstToken).setX509Certificate(remoteCert);
            bstToken.setID(certUri);
            ref.setValueType(bstToken.getValueType());
            secToken.setReference(ref);
            break;

        default:
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unsupportedKeyId");
        }
        
        keyInfo.addUnknownElement(secToken.getElement());
        WSSecurityUtil.appendChildElement(doc, xencEncryptedKey, keyInfo
                .getElement());

        Element xencCipherValue = createCipherValue(doc, xencEncryptedKey);
        xencCipherValue.appendChild(keyText);

        envelope = doc.getDocumentElement();
        envelope.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:"
                + WSConstants.ENC_PREFIX, WSConstants.ENC_NS);
        
        //Create the derived keys
        //At this point figure out the key length accordng to teh symencAlgo
        int offset = 0;
        int length = WSSecurityUtil.getKeyLength(this.symEncAlgo);
        byte[] label = ConversationConstants.DEFAULT_LABEL.getBytes("UTF-8");
        byte[] nonce = generateNonce();
        
        byte[] seed = new byte[label.length + nonce.length];
        System.arraycopy(label, 0, seed, 0, label.length);
        System.arraycopy(nonce, 0, seed, label.length, nonce.length);
        
        DerivationAlgorithm algo = AlgoFactory.getInstance(ConversationConstants.DerivationAlgorithm.P_SHA_1);
        
        this.derivedEncrKey = algo.createKey(this.ephemeralKey, seed, offset, length);
        
        
        //Add the DKTs
        dkt = new DerivedKeyToken(document);
        dkId = "derivedKeyId-" + dkt.hashCode();
        
        dkt.setLength(length);
        dkt.setNonce(Base64.encode(nonce));
        dkt.setOffset(offset);
        dkt.setID(dkId);
        //Create the SecurityTokenRef to the Encrypted Key
        SecurityTokenReference strEncKey = new SecurityTokenReference(document);
        Reference ref = new Reference(document);
        ref.setURI("#" + encKeyId);
        strEncKey.setReference(ref);
        dkt.setSecuityTokenReference(strEncKey);
    }
    
    /**
     * Encrypt one or more parts or elements of the message (external).
     * 
     * This method takes a vector of <code>WSEncryptionPart</code> object that
     * contain information about the elements to encrypt. The method call the
     * encryption method, takes the reference information generated during
     * encryption and add this to the <code>xenc:Reference</code> element.
     * This method can be called after <code>prepare()</code> and can be
     * called multiple times to encrypt a number of parts or elements.
     * 
     * </p>
     * 
     * The method generates a <code>xenc:Reference</code> element that <i>must</i>
     * be added to the SecurityHeader. See <code>addExternalRefElement()</code>.
     * 
     * </p>
     * 
     * If the <code>dataRef</code> parameter is <code>null</code> the method
     * creates and initializes a new Reference element.
     * 
     * @param dataRef
     *            A <code>xenc:Reference</code> element or <code>null</code>
     * @param references
     *            A vector containing WSEncryptionPart objects
     * @return Returns the updated <code>xenc:Reference</code> element
     * @throws WSSecurityException
     */
    public Element encryptForExternalRef(Element dataRef, Vector references)
            throws Exception {

        //Create the SecurityTokenRef to the DKT
        KeyInfo keyInfo = new KeyInfo(document);
        SecurityTokenReference secToken = new SecurityTokenReference(document);
        Reference ref = new Reference(document);
        ref.setURI("#" + dkId);
        secToken.setReference(ref);

        keyInfo.addUnknownElement(secToken.getElement());

        Vector encDataRefs = doEncryption(document, derivedEncrKey, keyInfo,
                references);
        Element referenceList = dataRef;
        if (referenceList == null) {
            referenceList = document.createElementNS(WSConstants.ENC_NS,
                    WSConstants.ENC_PREFIX + ":ReferenceList");
        }
        createDataRefList(document, referenceList, encDataRefs);
        return referenceList;
    }
    
    /**
     * Adds (prepends) the external Reference element to the Security header.
     * 
     * The reference element <i>must</i> be created by the
     * <code>encryptForExternalRef() </code> method. The method adds the
     * reference element in the SecurityHeader.
     * 
     * @param dataRef
     *            The external <code>enc:Reference</code> element
     * @param secHeader
     *            The security header.
     */
    public void addExternalRefElement(Element referenceList, WSSecHeader secHeader) {
        Node node = dkt.getElement().getNextSibling();
        if(node == null || (node != null && !(node instanceof Element))) {
            //If (at this moment) DerivedKeyToken is the LAST element of 
            //the security header 
            secHeader.getSecurityHeader().appendChild(referenceList);
        } else {
            secHeader.getSecurityHeader().insertBefore(referenceList, node);
        }
        
    }

    /**
     * @return
     */
    private byte[] getEphemeralKey() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] temp = new byte[16];
        random.nextBytes(temp);
        return temp;
    }
    
    /**
     * Prepend the DerivedKey element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the DereivedKey element at any position in the Security
     * header.
     * 
     * @param secHeader
     *            The security header that holds the Signature element.
     */
    public void prependDKElementToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(document, secHeader
            .getSecurityHeader(), dkt.getElement(), false);
    }
    
    
    /**
     * Prepend the EncryptedKey element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the EncryptedKey element at any position in the Security
     * header.
     * 
     * @param secHeader
     *            The security header that holds the Signature element.
     */
    public void prependToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(document, secHeader
                .getSecurityHeader(), xencEncryptedKey, false);
    }

    /**
     * Prepend the BinarySecurityToken to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the BST element at any position in the Security header.
     * 
     * @param secHeader
     *            The security header that holds the BST element.
     */
    public void prependBSTElementToHeader(WSSecHeader secHeader) {
        if (bstToken != null) {
            WSSecurityUtil.prependChildElement(document, secHeader
                    .getSecurityHeader(), bstToken.getElement(), false);
        }
        bstToken = null;
    }
    
    /**
     * Create DOM subtree for <code>xenc:EncryptedKey</code>
     * 
     * @param doc
     *            the SOAP enevelope parent document
     * @param keyTransportAlgo
     *            specifies which alogrithm to use to encrypt the symmetric key
     * @return an <code>xenc:EncryptedKey</code> element
     */
    public static Element createEnrcyptedKey(Document doc,
            String keyTransportAlgo) {
        Element encryptedKey = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":EncryptedKey");

        WSSecurityUtil.setNamespace(encryptedKey, WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX);
        Element encryptionMethod = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":EncryptionMethod");
        encryptionMethod.setAttributeNS(null, "Algorithm", keyTransportAlgo);
        WSSecurityUtil.appendChildElement(doc, encryptedKey, encryptionMethod);
        return encryptedKey;
    }
    
    public static Element createCipherValue(Document doc, Element encryptedKey) {
        Element cipherData = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":CipherData");
        Element cipherValue = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":CipherValue");
        cipherData.appendChild(cipherValue);
        WSSecurityUtil.appendChildElement(doc, encryptedKey, cipherData);
        return cipherValue;
    }
    

    public void setEncryptionUser(String user) {
        this.encrUser = user;
    }
    
    public static Element createDataRefList(Document doc,
            Element referenceList, Vector encDataRefs) {
        for (int i = 0; i < encDataRefs.size(); i++) {
            String dataReferenceUri = (String) encDataRefs.get(i);
            Element dataReference = doc.createElementNS(WSConstants.ENC_NS,
                    WSConstants.ENC_PREFIX + ":DataReference");
            dataReference.setAttributeNS(null, "URI", dataReferenceUri);
            referenceList.appendChild(dataReference);
        }
        return referenceList;
    }

    public void setSymmetricEncAlgorithm(String algo) {
        symEncAlgo = algo;
    }
}
