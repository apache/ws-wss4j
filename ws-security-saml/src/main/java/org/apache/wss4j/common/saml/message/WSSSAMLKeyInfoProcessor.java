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

package org.apache.wss4j.common.saml.message;

import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.api.dom.saml.SAMLKeyInfoProcessor;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.api.dom.processor.Processor;
import org.apache.wss4j.api.dom.processor.STRParserUtil;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.xml.security.utils.XMLUtils;

/**
 * This interface allows the user to plug in custom ways of processing a SAML KeyInfo.
 */
public class WSSSAMLKeyInfoProcessor implements SAMLKeyInfoProcessor {

    private static final String WST_NS = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    private static final String WST_NS_05_12 =
        "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

    private static final QName BINARY_SECRET =
        new QName(WST_NS, "BinarySecret");
    private static final QName BINARY_SECRET_05_12 =
        new QName(WST_NS_05_12, "BinarySecret");

    public SAMLKeyInfo processSAMLKeyInfoFromAssertionElement(Element assertionElement, RequestData data, 
        Crypto userCrypto) throws WSSecurityException {
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(assertionElement);
        return SAMLUtil.getCredentialFromSubject(samlAssertion, new WSSSAMLKeyInfoProcessor(), data, userCrypto);
    }

    public SAMLKeyInfo processSAMLKeyInfoFromSecurityTokenReference(SecurityTokenReference secRef,
        RequestData data
    ) throws WSSecurityException {
        SamlAssertionWrapper samlAssertion = getAssertionFromKeyIdentifier(secRef, secRef.getElement(), data);
        STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion.getSaml2() != null, data.getBSPEnforcer());

        return SAMLUtil.getCredentialFromSubject(samlAssertion, new WSSSAMLKeyInfoProcessor(), data, data.getSigVerCrypto());
    }

    public SAMLKeyInfo processSAMLKeyInfo(Element keyInfoElement, RequestData data) throws WSSecurityException {
        //
        // First try to find an EncryptedKey, BinarySecret or a SecurityTokenReference via DOM
        //
        if (keyInfoElement == null) {
            return null;
        }

        Node node = keyInfoElement.getFirstChild();
        while (node != null) {
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                QName el = new QName(node.getNamespaceURI(), node.getLocalName());
                if (el.equals(WSConstants.ENCRYPTED_KEY)) {
                    Processor proc = data.getWssConfig().getProcessor(WSConstants.ENCRYPTED_KEY);
                    AlgorithmSuite oldAlgorithmSuite = data.getAlgorithmSuite();
                    // Hack to work around hard-coding the EncryptedKeyProcessor
                    data.setAlgorithmSuite(data.getSamlAlgorithmSuite());
                    List<WSSecurityEngineResult> result = proc.handleToken((Element)node, data);
                    data.setAlgorithmSuite(oldAlgorithmSuite);
                    
                    byte[] secret =
                        (byte[])result.get(0).get(
                            WSSecurityEngineResult.TAG_SECRET
                        );
                    return new SAMLKeyInfo(secret);
                } else if (el.equals(BINARY_SECRET) || el.equals(BINARY_SECRET_05_12)) {
                    Text txt = (Text)node.getFirstChild();
                    return new SAMLKeyInfo(XMLUtils.decode(txt.getData()));
                } else if (SecurityTokenReference.STR_QNAME.equals(el)) {
                    /* TODO need to revisit STRParserParameters parameters = new STRParserParameters();
                    parameters.setData(data);
                    parameters.setStrElement((Element)node);

                    STRParser strParser = new SignatureSTRParser();
                    STRParserResult parserResult = strParser.parseSecurityTokenReference(parameters);
                    SAMLKeyInfo samlKeyInfo = new SAMLKeyInfo(parserResult.getCertificates());
                    samlKeyInfo.setPublicKey(parserResult.getPublicKey());
                    samlKeyInfo.setSecret(parserResult.getSecretKey());

                    Principal principal = parserResult.getPrincipal();

                    // Check for compliance against the defined AlgorithmSuite
                    AlgorithmSuite algorithmSuite = data.getSamlAlgorithmSuite();
                    if (algorithmSuite != null && principal instanceof WSDerivedKeyTokenPrincipal) {
                        AlgorithmSuiteValidator algorithmSuiteValidator = new
                            AlgorithmSuiteValidator(algorithmSuite);

                        algorithmSuiteValidator.checkDerivedKeyAlgorithm(
                            ((WSDerivedKeyTokenPrincipal)principal).getAlgorithm()
                        );
                        algorithmSuiteValidator.checkSignatureDerivedKeyLength(
                            ((WSDerivedKeyTokenPrincipal)principal).getLength()
                        );
                    }

                    return samlKeyInfo;
                    */
                }
            }
            node = node.getNextSibling();
        }

        return null;
    }

    /**
     * Get an SamlAssertionWrapper object from parsing a SecurityTokenReference that uses
     * a KeyIdentifier that points to a SAML Assertion.
     *
     * @param secRef the SecurityTokenReference to the SAML Assertion
     * @param strElement The SecurityTokenReference DOM element
     * @param request The RequestData instance used to obtain configuration
     * @return an SamlAssertionWrapper object
     * @throws WSSecurityException
     */
    private static SamlAssertionWrapper getAssertionFromKeyIdentifier(
        SecurityTokenReference secRef,
        Element strElement,
        RequestData request
    ) throws WSSecurityException {
        String keyIdentifierValue = secRef.getKeyIdentifierValue();
        String type = secRef.getKeyIdentifierValueType();
        WSSecurityEngineResult result = request.getWsDocInfo().getResult(keyIdentifierValue);

        SamlAssertionWrapper samlAssertion = null;
        Element token = null;
        if (result != null) {
            samlAssertion =
                (SamlAssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            return samlAssertion;
        } else {
            token =
            STRParserUtil.findProcessedTokenElement(
                    strElement.getOwnerDocument(), request.getWsDocInfo(), request.getCallbackHandler(),
                    keyIdentifierValue, type
                );
            if (token != null) {
                if (!"Assertion".equals(token.getLocalName())) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity"
                    );
                }
                return new SamlAssertionWrapper(token);
            }
            token =
                STRParserUtil.findUnprocessedTokenElement(
                    strElement.getOwnerDocument(), request.getWsDocInfo(), keyIdentifierValue, type
                );

            if (token == null || !"Assertion".equals(token.getLocalName())) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity"
                );
            }
            Processor proc = request.getWssConfig().getProcessor(WSConstants.SAML_TOKEN);
            List<WSSecurityEngineResult> samlResult = proc.handleToken(token, request);
            return
                (SamlAssertionWrapper)samlResult.get(0).get(
                    WSSecurityEngineResult.TAG_SAML_ASSERTION
                );
        }
    }
    
}
