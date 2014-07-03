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

import org.apache.neethi.Assertion;

/**
 * A interface that can be used to tell a third-part SOAP stack (e.g. Apache CXF) that WSS4J will
 * take care of asserting a certain policy, and thus can be marked as "asserted".
 */
public interface PolicyAsserter {

    void assertPolicy(Assertion assertion);
    
    void unassertPolicy(Assertion assertion, String reason);
    
    void assertPolicy(QName qName);
    
    void unassertPolicy(QName qName, String reason);
}
