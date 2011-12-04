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

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedPartSecurityEvent extends SecurityEvent {

    //todo xpath or something unique
    private QName element;
    private boolean encrypted; //if true this element is not encrypted.

    public EncryptedPartSecurityEvent(Event securityEventType, boolean encrypted) {
        super(securityEventType);
        this.encrypted = encrypted;
    }

    public QName getElement() {
        return element;
    }

    public void setElement(QName element) {
        this.element = element;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public void setEncrypted(boolean encrypted) {
        this.encrypted = encrypted;
    }
}
