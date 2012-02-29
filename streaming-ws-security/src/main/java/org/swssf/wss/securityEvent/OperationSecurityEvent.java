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

import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityContext;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class OperationSecurityEvent extends SecurityEvent {

    private QName operation;
    private WSSecurityContext wsSecurityContext;
    private WSSSecurityProperties wssSecurityProperties;

    public OperationSecurityEvent() {
        super(Event.Operation);
    }

    public QName getOperation() {
        return operation;
    }

    public void setOperation(QName operation) {
        this.operation = operation;
    }

    public WSSecurityContext getWsSecurityContext() {
        return wsSecurityContext;
    }

    public void setWsSecurityContext(WSSecurityContext wsSecurityContext) {
        this.wsSecurityContext = wsSecurityContext;
    }

    public WSSSecurityProperties getWssSecurityProperties() {
        return wssSecurityProperties;
    }

    public void setWssSecurityProperties(WSSSecurityProperties wssSecurityProperties) {
        this.wssSecurityProperties = wssSecurityProperties;
    }
}
