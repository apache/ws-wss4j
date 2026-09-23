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

package org.apache.wss4j.common.ext;

import java.lang.reflect.Field;
import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.xml.security.utils.I18n;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Santuario's I18n holds one static resource bundle for the whole JVM and ignores every attempt
 * to set it after the first, so the bundle WSS4J error messages are rendered from depends on
 * whether WSProviderConfig ran before anything else initialised Santuario. WSS4J message ids must
 * resolve either way.
 */
public class WSSecurityExceptionMessageTest {

    @BeforeAll
    public static void setup() throws Exception {
        WSProviderConfig.init();
    }

    /**
     * The case that used to degrade: Santuario was initialised first, so I18n holds the
     * xmlsecurity bundle and none of WSS4J's own message ids are in it. The message used to come
     * out as 'No message with ID "certpath" found in resource bundle "..."'.
     */
    @Test
    public void testWSS4JMessageIdResolvesWhenSantuarioOwnsTheBundle() throws Exception {
        ResourceBundle previous = installXMLSecBundle();
        try {
            WSSecurityException ex = new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "certpath", new Object[] {"No trusted certs found"});

            assertEquals("Error during certificate path validation: No trusted certs found", ex.getMessage());
        } finally {
            restoreBundle(previous);
        }
    }

    /**
     * A message id with no arguments, taken from the WSS4J bundle rather than formatted from it.
     */
    @Test
    public void testArgumentLessWSS4JMessageIdResolvesWhenSantuarioOwnsTheBundle() throws Exception {
        ResourceBundle previous = installXMLSecBundle();
        try {
            WSSecurityException ex = new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);

            assertEquals("General security error", ex.getMessage());
        } finally {
            restoreBundle(previous);
        }
    }

    /**
     * WSS4J also throws with message ids that belong to Santuario, such as "empty". Those are not
     * in wss4j_errors.properties and must keep being resolved by I18n.
     */
    @Test
    public void testSantuarioMessageIdIsLeftToI18n() throws Exception {
        WSSecurityException ex = new WSSecurityException(
            WSSecurityException.ErrorCode.FAILURE, "empty", new Object[] {"Attachment not found: cid:foo"});

        assertEquals("Attachment not found: cid:foo", ex.getMessage());
    }

    /**
     * The wrapped exception's message is the single argument, as I18n does it.
     */
    @Test
    public void testWrappedExceptionMessageIsUsedAsTheArgument() throws Exception {
        ResourceBundle previous = installXMLSecBundle();
        try {
            WSSecurityException ex = new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, new IllegalStateException("no path"), "certpath");

            assertEquals("Error during certificate path validation: no path", ex.getMessage());
        } finally {
            restoreBundle(previous);
        }
    }

    private static ResourceBundle installXMLSecBundle() throws Exception {
        ResourceBundle xmlSecBundle =
            ResourceBundle.getBundle("org/apache/xml/security/resource/xmlsecurity", Locale.US);
        return swapBundle(xmlSecBundle);
    }

    private static void restoreBundle(ResourceBundle previous) throws Exception {
        swapBundle(previous);
    }

    private static ResourceBundle swapBundle(ResourceBundle bundle) throws Exception {
        Field field;
        try {
            field = I18n.class.getDeclaredField("resourceBundle");
            field.setAccessible(true);  //NOPMD
        } catch (NoSuchFieldException | RuntimeException ex) {
            // I18n is not ours, so do not fail the build if it is reshaped or locked down
            Assumptions.abort("Cannot reach Santuario's I18n resource bundle: " + ex.getMessage());
            return null;
        }
        ResourceBundle previous = (ResourceBundle)field.get(null);
        field.set(null, bundle);
        return previous;
    }
}
