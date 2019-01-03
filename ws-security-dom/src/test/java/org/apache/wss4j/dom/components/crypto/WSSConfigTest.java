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

import java.security.Security;

import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

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

}