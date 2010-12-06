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

package org.apache.ws.security.components.crypto;

import org.apache.ws.security.common.CustomCrypto;

/**
 * Created by IntelliJ IDEA.
 * User: srida01
 * Date: Apr 12, 2004
 * Time: 10:50:05 AM
 * To change this template use File | Settings | File Templates.
 */
public class CryptoTest extends org.junit.Assert {
    
    @org.junit.Test
    public void testCrypto() {
        Crypto crypto = CryptoFactory.getInstance();
        assertTrue(crypto != null);
    }

    @org.junit.Test
    public void testAbstractCryptoWithNullProperties() 
        throws Exception {
        Crypto crypto = new NullPropertiesCrypto();
        assertTrue(crypto != null);
    }
    
    /**
     * Ensure that we can load a custom crypto implementation using a Map
     */
    @org.junit.Test
    public void testCustomCrypto() {
        java.util.Map<String, Object> tmp = new java.util.TreeMap<String, Object>();
        Crypto crypto = CryptoFactory.getInstance(
            "org.apache.ws.security.common.CustomCrypto",
            tmp
        );
        assertNotNull(crypto);
        assertTrue(crypto instanceof CustomCrypto);
        CustomCrypto custom = (CustomCrypto)crypto;
        assertSame(tmp, custom.getConfig());
    }
    
    /**
     * Test for WSS-149 - "AbstractCrypto requires org.apache.ws.security.crypto.merlin.file
     * to be set and point to an existing file"
     */
    @org.junit.Test
    public void testNoKeyStoreFile() {
        Crypto crypto = CryptoFactory.getInstance(
            "nofile.properties"
        );
        assertNotNull(crypto);
    }
    
    /**
     * WSS-102 -- ensure AbstractCrypto will null properties
     * can be instantiated
     */
    private static class NullPropertiesCrypto extends AbstractCrypto {
        public NullPropertiesCrypto() 
            throws Exception {
            super((java.util.Properties) null);
        }
    }
}
