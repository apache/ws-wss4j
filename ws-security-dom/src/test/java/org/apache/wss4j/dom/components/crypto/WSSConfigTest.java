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

package org.apache.wss4j.dom.components.crypto;

import java.security.Provider;
import java.security.Security;

import org.apache.wss4j.common.crypto.SantuarioUtil;
import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.transform.AttachmentContentSignatureTransformProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Test loading and removing security providers via WSSConfig
 */
public class WSSConfigTest {

    @Test
    public void testWSSConfig() {
        WSSConfig.cleanUp();
        WSSConfig.init();

        // Check providers
        assertNotNull(Security.getProvider("STRTransform"));
        assertNotNull(Security.getProvider("AttachmentContentSignatureTransform"));
        assertNotNull(Security.getProvider("AttachmentCompleteSignatureTransform"));
        assertNotNull(Security.getProvider("ApacheXMLDSig"));

        WSSConfig.cleanUp();

        assertNull(Security.getProvider("STRTransform"));
        assertNull(Security.getProvider("AttachmentContentSignatureTransform"));
        assertNull(Security.getProvider("AttachmentCompleteSignatureTransform"));
        assertNull(Security.getProvider("ApacheXMLDSig"));

    }

    @Test
    public void testWSProviderConfig() {
        WSProviderConfig.cleanUp();
        WSProviderConfig.init();

        // Check providers
        assertNotNull(Security.getProvider("ApacheXMLDSig"));

        WSProviderConfig.cleanUp();

        assertNull(Security.getProvider("ApacheXMLDSig"));

        WSProviderConfig.init(true, true, true);
        assertNotNull(Security.getProvider("ApacheXMLDSig"));
        assertNotNull(Security.getProvider("BC"));
        assertNotNull(Security.getProvider("TLSP"));

        WSProviderConfig.cleanUp();

        assertNull(Security.getProvider("ApacheXMLDSig"));
        assertNull(Security.getProvider("BC"));
        assertNull(Security.getProvider("TLSP"));

    }

    /**
     * WSS-660: cleanUp must not remove providers that were registered by someone else, e.g.
     * by a copy of WSS4J deployed in another web application, after we registered ours.
     */
    @Test
    public void testCleanUpLeavesForeignProviders() {
        WSSConfig.cleanUp();
        WSSConfig.init();

        // Simulate another copy of WSS4J replacing the providers
        Provider otherTransformProvider = new AttachmentContentSignatureTransformProvider();
        Security.removeProvider("AttachmentContentSignatureTransform");
        Security.addProvider(otherTransformProvider);

        Provider otherSantuarioProvider = SantuarioUtil.getSantuarioProvider();
        Security.removeProvider("ApacheXMLDSig");
        Security.addProvider(otherSantuarioProvider);

        try {
            WSSConfig.cleanUp();

            assertSame(otherTransformProvider, Security.getProvider("AttachmentContentSignatureTransform"));
            assertSame(otherSantuarioProvider, Security.getProvider("ApacheXMLDSig"));
            // The providers that were still ours are removed
            assertNull(Security.getProvider("STRTransform"));
            assertNull(Security.getProvider("AttachmentCompleteSignatureTransform"));
        } finally {
            Security.removeProvider("AttachmentContentSignatureTransform");
            Security.removeProvider("ApacheXMLDSig");
        }
    }

}
