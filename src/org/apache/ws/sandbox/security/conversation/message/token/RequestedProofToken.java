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
package org.apache.ws.security.conversation.message.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.util.DOM2Writer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

/**
 * Class RequestedProofToken
 */
public class RequestedProofToken {

    /**
     * Field log
     */
    private static Log log =
        LogFactory.getLog(RequestedProofToken.class.getName());

    /**
     * Field TOKEN
     */
    public static final QName TOKEN =
        new QName(WSConstants.WSSE_NS, "RequestedProofToken");

    /**
     * Field proofEle
     */
    private Element proofEle;

    /**
     * Field keyInfoEle
     */
    private Element keyInfoEle;

    /**
     * Field mgmtDataEle
     */
    private Element mgmtDataEle;

    /**
     * Field sharedSecret
     */
    private byte[] sharedSecret = null;

    // TODO :: Change this .............

    /**
     * Field encCrypto
     */
    private Crypto encCrypto = null;

    /**
     * Field doDebug
     */
    private boolean doDebug = false;

    /**
     * Field base
     */
    private BaseToken base;

    /**
     * Field symEncAlgo
     */
    protected String symEncAlgo = WSConstants.TRIPLE_DES;

    /**
     * Field keyEncAlgo
     */
    protected String keyEncAlgo = WSConstants.KEYTRANSPORT_RSA15;

    /*
     * The RequestedProofToken look like this.
     *
     *  <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/04/xmldsig#' >
     *    <ds:MgmtData>i3jTGW6PnDuf4ax603i20A==</ds:MgmtData>
     *   </ds:KeyInfo>
     */

    /**
     * Constructor.
     * 
     * @param doc    is the SOAP envelop.
     * @param secret is the secret.
     * @throws WSSecurityException 
     */
    public RequestedProofToken(Document doc) throws WSSecurityException {
        this.proofEle =
            doc.createElementNS(
                WSConstants.WSSE_NS,
                "wsse:RequestedProofToken");
        System.out.println("RequestedProofToken....... created .....");
    }

    /**
     * COnstructor
     * 
     * @param elem 
     * @throws WSSecurityException 
     */
    public RequestedProofToken(Element elem) throws WSSecurityException {
        doDebug = log.isDebugEnabled();
        QName el = new QName(elem.getNamespaceURI(), elem.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "badElement",
                new Object[] { TOKEN, el });
        }
        this.proofEle = elem;
    }

    /**
     * Method doDecryption
     * 
     * @param callback 
     * @param crypto   
     * @throws WSSecurityException 
     */
    public void doDecryption(String callback, Crypto crypto)
        throws WSSecurityException {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        CallbackHandler cbHandler;

        // Element
        NodeList ndList =
            this.proofEle.getElementsByTagNameNS(
                "http://www.w3.org/2001/04/xmlenc#",
                "EncryptedKey");
        if (ndList.getLength() < 1) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                "RequestedProofToken is empty");
        }

        // CbHandler :: taken from WSSecurityEngine class
        if (callback != null) {
            Class cbClass = null;
            try {
                cbClass = java.lang.Class.forName(callback);
            } catch (ClassNotFoundException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_ENC_DEC,
                    "RequestedProofToken: cannot load password callback class: "
                        + callback);
            }
            try {
                cbHandler = (CallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_ENC_DEC,
                    "RequestedProofToken: cannot create instance of password callback: "
                        + callback);
            }
            secEngine.handleEncryptedKey(
                (Element) ndList.item(0),
                cbHandler,
                crypto);

            this.sharedSecret = secEngine.getDecryptedBytes();
            System.out.println(new String(this.sharedSecret));
        } else {
            System.out.println("Do somehting....... Decryption problem");
        }
    }

    /**
     * Method doEncryptProof
     * 
     * @param doc 
     */
    public void doEncryptProof(Document doc) throws WSSecurityException {
        WSEncryptBody wsEncrypt = new WSEncryptBody();

        try {
            Crypto crypto;
            crypto = CryptoFactory.getInstance("crypto.properties");
            wsEncrypt.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
            wsEncrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");

            wsEncrypt.setParentNode(
                (Element) (doc
                    .getElementsByTagNameNS(
                        WSConstants.WSSE_NS,
                        "RequestedProofToken")
                    .item(0)));
            wsEncrypt.build(doc, crypto);
            this.sharedSecret = wsEncrypt.getSymmetricKey().getEncoded();

        } catch (WSSecurityException e) {
            e.printStackTrace();
        }
    }

    /**
     * Method getElement
     * 
     * @return 
     */
    public Element getElement() {
        return this.proofEle;
    }

    /**
     * @return 
     */
    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    /**
     * Method getID
     * 
     * @return 
     */
    public String getID() {
        return this.proofEle.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * Method toString
     * 
     * @return 
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.proofEle);
    }
}
