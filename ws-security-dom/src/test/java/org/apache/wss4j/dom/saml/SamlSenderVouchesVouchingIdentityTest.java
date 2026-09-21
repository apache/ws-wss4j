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

package org.apache.wss4j.dom.saml;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A sender-vouches assertion is a claim made by whoever sent the message, so it is worth exactly as
 * much as that sender's identity. An assertion that is itself signed carries its issuer's signature,
 * which is trust-verified separately; an unsigned one does not, and the only thing asserting it is
 * the signature over the message. That signature therefore has to have been made with a credential
 * whose identity was established - not merely with a key the sender happens to hold, such as one
 * taken from an EncryptedKey the sender minted for itself.
 */
public class SamlSenderVouchesVouchingIdentityTest {

    private final Crypto crypto;

    public SamlSenderVouchesVouchingIdentityTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * The shape of the bypass: an unsigned sender-vouches assertion, and a signature that covers it
     * and the Body but was verified with a bare symmetric key, so it says nothing about who sent it.
     */
    @Test
    public void testUnsignedAssertionRejectsUnidentifiedSigner() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SamlAssertionWrapper assertion = senderVouchesAssertion(doc, false);
        Element body = WSSecurityUtil.findBodyElement(doc);

        List<WSSecurityEngineResult> signed = Collections.singletonList(
            coveringSignature(WSConstants.SIGN, false, assertion.getElement(), body));

        assertFalse(DOMSAMLUtil.checkSenderVouches(assertion, null, body, signed),
            "An unsigned sender-vouches assertion must not be accepted on the word of a signer "
            + "whose identity was never established");
    }

    /**
     * The same coverage from a credential a Validator made a trust decision about is what
     * sender-vouches is supposed to look like.
     */
    @Test
    public void testUnsignedAssertionAcceptsTrustValidatedSigner() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SamlAssertionWrapper assertion = senderVouchesAssertion(doc, false);
        Element body = WSSecurityUtil.findBodyElement(doc);

        List<WSSecurityEngineResult> signed = Collections.singletonList(
            coveringSignature(WSConstants.SIGN, true, assertion.getElement(), body));

        assertTrue(DOMSAMLUtil.checkSenderVouches(assertion, null, body, signed));
    }

    /**
     * A UsernameToken derived key is never stamped as a validated token, but deriving it required
     * the password, so the sender is authenticated and may vouch.
     */
    @Test
    public void testUnsignedAssertionAcceptsUsernameTokenSigner() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SamlAssertionWrapper assertion = senderVouchesAssertion(doc, false);
        Element body = WSSecurityUtil.findBodyElement(doc);

        List<WSSecurityEngineResult> signed = Collections.singletonList(
            coveringSignature(WSConstants.UT_SIGN, false, assertion.getElement(), body));

        assertTrue(DOMSAMLUtil.checkSenderVouches(assertion, null, body, signed));
    }

    /**
     * An assertion signed by its issuer already carries a vouching identity of its own - the
     * message signature only binds it to this message - so the symmetric-binding deployments that
     * rely on that pattern must keep working.
     */
    @Test
    public void testSignedAssertionAcceptsAnySigner() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SamlAssertionWrapper assertion = senderVouchesAssertion(doc, true);
        assertTrue(assertion.isSigned(), "precondition: the assertion is signed");
        Element body = WSSecurityUtil.findBodyElement(doc);

        List<WSSecurityEngineResult> signed = Collections.singletonList(
            coveringSignature(WSConstants.SIGN, false, assertion.getElement(), body));

        assertTrue(DOMSAMLUtil.checkSenderVouches(assertion, null, body, signed));
    }

    private SamlAssertionWrapper senderVouchesAssertion(Document doc, boolean sign) throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);

        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        if (sign) {
            samlAssertion.signAssertion("16c73ab6-b892-458f-abf5-2f875f74882e", "security",
                                        crypto, false);
        }
        samlAssertion.toDOM(doc);
        return samlAssertion;
    }

    /**
     * A signature result covering the given elements. {@code validated} is what
     * SignatureProcessor stamps when a trust decision was actually taken on the signing credential.
     */
    private WSSecurityEngineResult coveringSignature(
        int action, boolean validated, Element... protectedElements
    ) {
        List<WSDataRef> dataRefs = new ArrayList<>();
        for (Element protectedElement : protectedElements) {
            WSDataRef dataRef = new WSDataRef();
            dataRef.setProtectedElement(protectedElement);
            dataRefs.add(dataRef);
        }

        WSSecurityEngineResult result = new WSSecurityEngineResult(action);
        result.put(WSSecurityEngineResult.TAG_DATA_REF_URIS, dataRefs);
        if (validated) {
            result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
        }
        return result;
    }
}
