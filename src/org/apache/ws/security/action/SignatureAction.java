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

package org.apache.ws.security.action;

import java.util.Vector;

import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SignatureAction implements Action {
    public void execute(WSHandler handler, int actionToDo, Document doc, RequestData reqData)
            throws WSSecurityException {
        WSPasswordCallback pwcb =
            handler.getPassword(
                reqData.getSignatureUser(),
                actionToDo,
                WSHandlerConstants.PW_CALLBACK_CLASS,
                WSHandlerConstants.PW_CALLBACK_REF, reqData
            );

        WSSecSignature wsSign = new WSSecSignature();
        wsSign.setWsConfig(reqData.getWssConfig());

        if (reqData.getSigKeyId() != 0) {
            wsSign.setKeyIdentifierType(reqData.getSigKeyId());
        }
        if (reqData.getSigAlgorithm() != null) {
            wsSign.setSignatureAlgorithm(reqData.getSigAlgorithm());
        }
        if (reqData.getSigDigestAlgorithm() != null) {
            wsSign.setDigestAlgo(reqData.getSigDigestAlgorithm());
        }

        wsSign.setUserInfo(reqData.getSignatureUser(), pwcb.getPassword());
        wsSign.setUseSingleCertificate(reqData.isUseSingleCert());
        if (reqData.getSignatureParts().size() > 0) {
            wsSign.setParts(reqData.getSignatureParts());
        }
        
        if (pwcb.getKey() != null) {
            wsSign.setSecretKey(pwcb.getKey());
        }

        try {
            wsSign.prepare(doc, reqData.getSigCrypto(), reqData.getSecHeader());
            
            Element siblingElementToPrepend = null;
            Vector signatureParts = reqData.getSignatureParts();
            if (signatureParts == null) {
                signatureParts = new Vector();
                SOAPConstants soapConstants = 
                    WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
                WSEncryptionPart encP = 
                    new WSEncryptionPart(
                        soapConstants.getBodyQName().getLocalPart(), 
                        soapConstants.getEnvelopeURI(), 
                        "Content"
                    );
                signatureParts.add(encP);
            } else if (reqData.isAppendSignatureAfterTimestamp() && signatureParts != null) {
                for (int i = 0; i < signatureParts.size(); i++) {
                    WSEncryptionPart part = 
                        (WSEncryptionPart)signatureParts.get(i);
                    if (WSConstants.WSU_NS.equals(part.getNamespace()) 
                            && "Timestamp".equals(part.getName())) {
                        Element timestampElement = 
                                (Element)WSSecurityUtil.findElement(
                                        doc.getDocumentElement(), part.getName(), part.getNamespace()
                                );
                        if (timestampElement != null) {
                            Node child = timestampElement.getNextSibling();
                            while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
                                child = child.getNextSibling();
                            }
                            siblingElementToPrepend = (Element)child;
                        }
                    }
                }
            }
            
            wsSign.addReferencesToSign(signatureParts, reqData.getSecHeader());
            
            if (reqData.isAppendSignatureAfterTimestamp()) {
                if (siblingElementToPrepend == null) {
                    wsSign.appendToHeader(reqData.getSecHeader());
                } else {
                    reqData.getSecHeader().getSecurityHeader().insertBefore(
                        wsSign.getSignatureElement(), siblingElementToPrepend
                    );
                }
            } else {
                wsSign.prependToHeader(reqData.getSecHeader());
            }

            wsSign.prependBSTElementToHeader(reqData.getSecHeader());
            wsSign.computeSignature();

            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("Error during Signature: ", e);
        }
    }

}
