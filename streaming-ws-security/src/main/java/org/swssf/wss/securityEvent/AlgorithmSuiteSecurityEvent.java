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
package org.swssf.wss.securityEvent;


import org.apache.xml.security.stax.ext.XMLSecurityConstants;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class AlgorithmSuiteSecurityEvent extends SecurityEvent {

    //@see http://docs.oasis-open.org/ws-sx/ws-securitypolicy/v1.3/os/ws-securitypolicy-1.3-spec-os.html
    //chapter 6.1

    private int keyLength;
    private String algorithmURI;
    private XMLSecurityConstants.KeyUsage keyUsage;

    public AlgorithmSuiteSecurityEvent() {
        super(Event.AlgorithmSuite);
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public String getAlgorithmURI() {
        return algorithmURI;
    }

    public void setAlgorithmURI(String algorithmURI) {
        this.algorithmURI = algorithmURI;
    }

    public XMLSecurityConstants.KeyUsage getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(XMLSecurityConstants.KeyUsage keyUsage) {
        this.keyUsage = keyUsage;
    }
}
