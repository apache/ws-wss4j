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
package org.apache.wss4j.stax.ext;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.SecurePart;

/**
 * Extend the Apache Santuario SecurePart class with some additional configuration for WSS
 */
public class WSSSecurePart extends SecurePart {

    private String idToReference;

    public WSSSecurePart(Modifier modifier) {
        super(modifier);
    }

    public WSSSecurePart(QName name, Modifier modifier) {
        super(name, modifier);
    }

    public WSSSecurePart(QName name, Modifier modifier, String[] transforms, String digestMethod) {
        super(name, modifier, transforms, digestMethod);
    }

    public WSSSecurePart(QName name, boolean generateXPointer, Modifier modifier) {
        super(name, generateXPointer, modifier);
    }

    public WSSSecurePart(QName name, boolean generateXPointer, Modifier modifier, String[] transforms, String digestMethod) {
        super(name, generateXPointer, modifier, transforms, digestMethod);
    }

    public WSSSecurePart(String externalReference) {
        super(externalReference);
    }

    public WSSSecurePart(String externalReference, Modifier modifier) {
        super(externalReference, modifier);
    }

    public WSSSecurePart(String externalReference, String[] transforms, String digestMethod) {
        super(externalReference, transforms, digestMethod);
    }

    public String getIdToReference() {
        return idToReference;
    }

    public void setIdToReference(String idToReference) {
        this.idToReference = idToReference;
    }
}
