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
package org.swssf.wss.ext;

import org.swssf.xmlsec.ext.DocumentContext;

/**
 * This class holds per document, context informations
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface WSSDocumentContext extends DocumentContext {

    /**
     * @return The SOAP Version used
     */
    public String getSOAPMessageVersionNamespace();

    /**
     * Indicates if we are currently processing the soap header
     *
     * @return true if we stay in the soap header, false otherwise
     */
    public boolean isInSOAPHeader();

    /**
     * Indicates if we are currently processing the soap body
     *
     * @return true if we stay in the soap body, false otherwise
     */
    public boolean isInSOAPBody();

    /**
     * Indicates if we are currently processing the security header
     *
     * @return true if we stay in the security header, false otherwise
     */
    public boolean isInSecurityHeader();

    /**
     * Specifies that we are now in the security header
     *
     * @param inSecurityHeader set to true when we entering the security header, false otherwise
     */
    public void setInSecurityHeader(boolean inSecurityHeader);

}
