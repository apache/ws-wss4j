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
package org.apache.wss4j.policy.stax;

import javax.xml.namespace.QName;

import org.apache.neethi.Policy;

public class OperationPolicy {

    private QName operationName;
    private String operationAction;
    private Policy policy;
    private String soapMessageVersionNamespace;

    public OperationPolicy(QName operationName) {
        this.operationName = operationName;
    }

    public QName getOperationName() {
        return operationName;
    }

    public void setOperationName(QName operationName) {
        this.operationName = operationName;
    }

    public String getOperationAction() {
        return operationAction;
    }

    public void setOperationAction(String operationAction) {
        this.operationAction = operationAction;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public String getSoapMessageVersionNamespace() {
        return soapMessageVersionNamespace;
    }

    public void setSoapMessageVersionNamespace(String soapMessageVersionNamespace) {
        this.soapMessageVersionNamespace = soapMessageVersionNamespace;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof OperationPolicy)) {
            return false;
        }
        OperationPolicy other = (OperationPolicy) obj;
        return getOperationName().equals(other.getOperationName());
    }
    
    @Override
    public int hashCode() {
        int hashcode = 17;
        if (getOperationName() != null) {
            hashcode *= 31 * getOperationName().hashCode();
        }
        return hashcode;
    }
}
