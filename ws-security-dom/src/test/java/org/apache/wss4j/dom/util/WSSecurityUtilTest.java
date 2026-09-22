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

package org.apache.wss4j.dom.util;

import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;


public class WSSecurityUtilTest {

    @Test
    public void testNewEncryptionAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPTION;
        List<Integer> decodeActions = WSSecurityUtil.decodeAction(action);
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0));
        assertEquals(WSConstants.ENCR, decodeActions.get(1));
    }

    @Test
    public void testNewEncryptionHandlerAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPTION;
        List<HandlerAction> decodeActions = WSSecurityUtil.decodeHandlerAction(action, WSSConfig.getNewInstance());
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0).getAction());
        assertEquals(WSConstants.ENCR, decodeActions.get(1).getAction());
    }

    @Test
    public void testDeprecatedEncryptionAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPT;
        List<Integer> decodeActions = WSSecurityUtil.decodeAction(action);
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0));
        assertEquals(WSConstants.ENCR, decodeActions.get(1));
    }

    @Test
    public void testDeprecatedEncryptionHandlerAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPT;
        List<HandlerAction> decodeActions = WSSecurityUtil.decodeHandlerAction(action, WSSConfig.getNewInstance());
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0).getAction());
        assertEquals(WSConstants.ENCR, decodeActions.get(1).getAction());
    }

    @Test
    public void testNewEncryptionDerivedAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPTION_DERIVED;
        List<Integer> decodeActions = WSSecurityUtil.decodeAction(action);
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0));
        assertEquals(WSConstants.DKT_ENCR, decodeActions.get(1));
    }

    @Test
    public void testNewEncryptionHandlerDerivedAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPTION_DERIVED;
        List<HandlerAction> decodeActions = WSSecurityUtil.decodeHandlerAction(action, WSSConfig.getNewInstance());
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0).getAction());
        assertEquals(WSConstants.DKT_ENCR, decodeActions.get(1).getAction());
    }

    @Test
    public void testDeprecatedEncryptionDerivedAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPT_DERIVED;
        List<Integer> decodeActions = WSSecurityUtil.decodeAction(action);
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0));
        assertEquals(WSConstants.DKT_ENCR, decodeActions.get(1));
    }

    @Test
    public void testDeprecatedEncryptionHandlerDerivedAction() throws Exception {
        String action = ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.ENCRYPT_DERIVED;
        List<HandlerAction> decodeActions = WSSecurityUtil.decodeHandlerAction(action, WSSConfig.getNewInstance());
        assertEquals(2, decodeActions.size());
        assertEquals(WSConstants.SIGN, decodeActions.get(0).getAction());
        assertEquals(WSConstants.DKT_ENCR, decodeActions.get(1).getAction());
    }

    /**
     * An xop:Include that names no attachment has no attachment bytes to inline, so it is left
     * as it is. It used to be read as an attachment reference regardless - getAttributeNS
     * answers an absent attribute with "", never null - and "" parsed as an attachment id threw
     * StringIndexOutOfBoundsException out of the engine.
     */
    @Test
    public void testInlineAttachmentsIgnoresIncludeThatNamesNoAttachment() throws Exception {
        for (String href : new String[] {null, "", "x", "#foo", "http://example.com/a"}) {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            Element include = doc.createElementNS(WSConstants.XOP_NS, "xop:Include");
            if (href != null) {
                include.setAttributeNS(null, "href", href);
            }
            doc.getDocumentElement().appendChild(include);

            WSSecurityUtil.inlineAttachments(
                Collections.singletonList(include), rejectingAttachmentCallbackHandler(), true);

            assertSame(include, doc.getDocumentElement().getLastChild(),
                       "The Include should have been left alone for href " + href);
        }
    }

    /**
     * An Include that does name an attachment is still resolved, and a failure to resolve it is
     * reported as a WSSecurityException.
     */
    @Test
    public void testInlineAttachmentsResolvesCidHref() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        Element include = doc.createElementNS(WSConstants.XOP_NS, "xop:Include");
        include.setAttributeNS(null, "href", "cid:missing");
        doc.getDocumentElement().appendChild(include);

        assertThrows(WSSecurityException.class,
            () -> WSSecurityUtil.inlineAttachments(
                      Collections.singletonList(include), rejectingAttachmentCallbackHandler(), true));
    }

    private static CallbackHandler rejectingAttachmentCallbackHandler() {
        // Non-null, so that getBytesFromAttachment gets as far as parsing the URI
        return callbacks -> {
            throw new UnsupportedCallbackException(callbacks[0]);
        };
    }

}