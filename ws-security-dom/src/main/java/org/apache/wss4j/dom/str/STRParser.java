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

package org.apache.wss4j.dom.str;

import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * This interface describes a pluggable way of extracting credentials from SecurityTokenReference
 * elements. The implementations are used by various processors.
 */
public interface STRParser {

    /**
     * ISSUER_SERIAL - A certificate (chain) is located by the issuer name and serial number of the
     * (root) cert
     * THUMBPRINT_SHA1 - A certificate (chain) is located by the SHA1 thumbprint of the (root) cert
     * KEY_IDENTIFIER - A certificate (chain) is located via a Key Identifier Element
     * DIRECT_REF - A certificate (chain) is located directly via an Id to another security token
     * Note that a Thumbprint reference is also a KeyIdentifier, but takes precedence over it.
     */
    enum REFERENCE_TYPE {
        ISSUER_SERIAL, THUMBPRINT_SHA1, KEY_IDENTIFIER, DIRECT_REF
    }

    /**
     * Parse a SecurityTokenReference element and extract credentials.
     *
     * @param parameters The parameters to parse
     * @return the STRParserResult Object containing the parsing results
     * @throws WSSecurityException
     */
    STRParserResult parseSecurityTokenReference(STRParserParameters parameters) throws WSSecurityException;

}
