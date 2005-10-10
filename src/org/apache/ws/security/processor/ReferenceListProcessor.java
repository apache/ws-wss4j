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

package org.apache.ws.security.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import java.util.Vector;

public class ReferenceListProcessor implements Processor {
    private static Log log = LogFactory.getLog(ReferenceListProcessor.class.getName());

    public void handleToken(Element elem, Crypto crypto, Crypto decCrypto, CallbackHandler cb, WSDocInfo wsDocInfo, Vector returnResults, WSSConfig wsc) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found reference list element");
        }
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "noCallback");
        }
        handleReferenceList((Element) elem, cb);
        returnResults.add(0, new WSSecurityEngineResult(WSConstants.ENCR, null, null, null, null));
    }

    /**
     * Dereferences and decodes encrypted data elements.
     *
     * @param elem contains the <code>ReferenceList</code> to the
     *             encrypted data elements
     * @param cb   the callback handler to get the key for a key name
     *             stored if <code>KeyInfo</code> inside the encrypted
     *             data elements
     */
    private void handleReferenceList(Element elem, CallbackHandler cb)
            throws WSSecurityException {

        Document doc = elem.getOwnerDocument();

        Node tmpE = null;
        for (tmpE = elem.getFirstChild();
             tmpE != null;
             tmpE = tmpE.getNextSibling()) {
            if (tmpE.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            if (!tmpE.getNamespaceURI().equals(WSConstants.ENC_NS)) {
                continue;
            }
            if (tmpE.getLocalName().equals("DataReference")) {
                String dataRefURI = ((Element) tmpE).getAttribute("URI");
                decryptDataRefEmbedded(doc, dataRefURI, cb);
            }
        }
    }

    public void decryptDataRefEmbedded(Document doc,
                                       String dataRefURI,
                                       CallbackHandler cb)
            throws WSSecurityException {

        if (log.isDebugEnabled()) {
            log.debug("Embedded found data refernce: " + dataRefURI);
        }
        /*
         * Look up the encrypted data. First try wsu:Id="someURI". If no such Id then
         * try the generic lookup to find Id="someURI"
         */
        Element encBodyData = null;
        if ((encBodyData = WSSecurityUtil.getElementByWsuId(doc, dataRefURI)) == null) {
            encBodyData = WSSecurityUtil.getElementByGenId(doc, dataRefURI);
        }
        if (encBodyData == null) {
            throw new WSSecurityException
                    (WSSecurityException.INVALID_SECURITY,
                            "dataRef", new Object[]{dataRefURI});
        }

        boolean content = X509Util.isContent(encBodyData);

        // Now figure out the encryption algorithm
        String symEncAlgo = X509Util.getEncAlgo(encBodyData);

        Element tmpE =
                (Element) WSSecurityUtil.findElement((Node) encBodyData,
                        "KeyInfo",
                        WSConstants.SIG_NS);

        SecretKey symmetricKey = X509Util.getSharedKey(tmpE, symEncAlgo, cb);

        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException e1) {
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e1);
        }

        if (content) {
            encBodyData = (Element) encBodyData.getParentNode();
        }
        try {
            xmlCipher.doFinal(doc, encBodyData, content);
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e);
        }
    }

}
