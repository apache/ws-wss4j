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

import org.apache.wss4j.stax.setup.WSSec;
import org.apache.xml.security.stax.config.ConfigurationProperties;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test that the configuration defaults defined in security-config.xml in Santuario are still picked up
 * correctly via wss-config.xml
 */
public class ConfigurationPropertiesTest extends AbstractTestBase {

    /*
        <Property NAME="MaximumAllowedTransformsPerReference" VAL="5"/>
        <Property NAME="MaximumAllowedReferencesPerManifest" VAL="30"/>
        <Property NAME="DoNotThrowExceptionForManifests" VAL="false"/>
        <Property NAME="AllowMD5Algorithm" VAL="false"/>
        <Property NAME="MaximumAllowedXMLStructureDepth" VAL="100"/>
        <Property NAME="MaximumAllowedEncryptedDataEvents" VAL="200"/>
     */
    @Test
    public void testConfigurationProperties() throws Exception {
        WSSec.init();
        assertEquals("5", ConfigurationProperties.getProperty("MaximumAllowedTransformsPerReference"));
        assertEquals("30", ConfigurationProperties.getProperty("MaximumAllowedReferencesPerManifest"));
        assertEquals("false", ConfigurationProperties.getProperty("DoNotThrowExceptionForManifests"));
        assertEquals("false", ConfigurationProperties.getProperty("AllowMD5Algorithm"));
        assertEquals("100", ConfigurationProperties.getProperty("MaximumAllowedXMLStructureDepth"));
        assertEquals("5", ConfigurationProperties.getProperty("MaximumAllowedTransformsPerReference"));
        assertEquals("200", ConfigurationProperties.getProperty("MaximumAllowedEncryptedDataEvents"));

        // This one is overridden in wss-config.xml
        assertEquals("true", ConfigurationProperties.getProperty("AllowNotSameDocumentReferences"));
    }

}