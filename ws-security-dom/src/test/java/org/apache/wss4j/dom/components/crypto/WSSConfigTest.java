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

/**
 * Test loading and removing security providers via WSSConfig
 */
public class WSSConfigTest extends org.junit.Assert {

    @Test
    public void testWSSConfig() {
        WSSConfig.cleanUp();
        WSSConfig.init();

        // Check providers
        assertTrue(Security.getProvider("STRTransform") != null);
        assertTrue(Security.getProvider("AttachmentContentSignatureTransform") != null);
        assertTrue(Security.getProvider("AttachmentCompleteSignatureTransform") != null);
        assertTrue(Security.getProvider("ApacheXMLDSig") != null);

        WSSConfig.cleanUp();

        assertTrue(Security.getProvider("STRTransform") == null);
        assertTrue(Security.getProvider("AttachmentContentSignatureTransform") == null);
        assertTrue(Security.getProvider("AttachmentCompleteSignatureTransform") == null);
        assertTrue(Security.getProvider("ApacheXMLDSig") == null);

    }

    @Test
    public void testWSProviderConfig() {
        WSProviderConfig.cleanUp();
        WSProviderConfig.init();

        // Check providers
        assertTrue(Security.getProvider("ApacheXMLDSig") != null);

        WSProviderConfig.cleanUp();

        assertTrue(Security.getProvider("ApacheXMLDSig") == null);

        WSProviderConfig.init(true, true, true);
        assertTrue(Security.getProvider("ApacheXMLDSig") != null);
        assertTrue(Security.getProvider("BC") != null);
        assertTrue(Security.getProvider("TLSP") != null);

        WSProviderConfig.cleanUp();

        assertTrue(Security.getProvider("ApacheXMLDSig") == null);
        assertTrue(Security.getProvider("BC") == null);
        assertTrue(Security.getProvider("TLSP") == null);

    }

}
