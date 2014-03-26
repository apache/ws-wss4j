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
package org.apache.wss4j.stax.impl;

import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.XMLSecurityStreamReader;

import javax.xml.stream.XMLStreamException;

public class WSSecurityStreamReader extends XMLSecurityStreamReader {
    
    private final boolean initiator;
    
    public WSSecurityStreamReader(InputProcessorChain inputProcessorChain, 
            XMLSecurityProperties securityProperties, boolean initiator) {
        super(inputProcessorChain, securityProperties);
        this.initiator = initiator;
    }

    @Override
    public int next() throws XMLStreamException {
        try {
            return super.next();
        } catch (XMLStreamException e) {
            Throwable cause = e.getCause();
            if (cause instanceof WSSecurityException) {
                // Allow a WSSPolicyException
                if (initiator || cause.getCause() instanceof WSSPolicyException) {
                    throw e;
                }
                // Map to a "safe" error message if we are not the initiator
                String error = ((WSSecurityException)cause).getSafeExceptionMessage();
                throw new XMLStreamException(
                    new WSSecurityException(((WSSecurityException)cause).getErrorCode(),
                                            new Exception(error)));
            }
            if (cause instanceof XMLSecurityException) {
                throw new XMLStreamException(
                        new WSSecurityException(
                                WSSecurityException.ErrorCode.FAILED_CHECK, (XMLSecurityException)cause));
            }
            throw e;
        }
    }
    
}
