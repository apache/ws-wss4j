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
package org.apache.wss4j.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.stream.XMLStreamException;

import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.xml.security.stax.config.Init;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class VulnerabliltyVectorsDecompressedBytesTest extends AbstractTestBase {

    @BeforeAll
    public static void setup() throws Exception {
        WSSec.init();
        Init.init(VulnerabliltyVectorsDecompressedBytesTest.class.getClassLoader().getResource("wss-config-compression.xml").toURI(),
                VulnerabliltyVectorsDecompressedBytesTest.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testMaximumAllowedDecompressedBytes() throws Exception {

        try {
            WSSSecurityProperties outboundSecurityProperties = new WSSSecurityProperties();
            outboundSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
            outboundSecurityProperties.setEncryptionUser("receiver");
            outboundSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            outboundSecurityProperties.setSignatureUser("transmitter");
            outboundSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.TIMESTAMP);
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPTION);
            outboundSecurityProperties.setActions(actions);
            outboundSecurityProperties.setEncryptionCompressionAlgorithm("http://www.apache.org/2012/04/xmlsec/xz");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            ByteArrayOutputStream baos = doOutboundSecurity(outboundSecurityProperties, sourceDocument);


            WSSSecurityProperties inboundSecurityProperties = new WSSSecurityProperties();
            inboundSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
            inboundSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            inboundSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

            doInboundSecurity(inboundSecurityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof IOException);
            assertEquals(e.getCause().getMessage(),
                    "Maximum byte count (101) reached.");
        }
    }

}