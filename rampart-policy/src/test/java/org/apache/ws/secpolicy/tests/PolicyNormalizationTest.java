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
package org.apache.ws.secpolicy.tests;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;

import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PolicyNormalizationTest extends AbstractTestBase {

    public void testWSP15_432Normalization() throws Exception {
        String fileName = "WSP15_432-compact.xml";
        String policyFile = loadPolicyFile("policy/" + fileName);
        String serializedPolicyReferenceFile = loadPolicyFile("policy/WSP15_432-serialized.xml");
        String normalizedPolicyReferenceFile = loadPolicyFile("policy/WSP15_432-normalized.xml");
        Policy policy = loadPolicy(policyFile);
        String serializedPolicy = serializePolicy(policy);
        assertXMLisEqual(serializedPolicy, serializedPolicyReferenceFile);

        policy = policy.normalize(true);
        Iterator<List<Assertion>> iterator = policy.getAlternatives();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(37, count);
        serializedPolicy = serializePolicy(policy);
        assertXMLisEqual(serializedPolicy, normalizedPolicyReferenceFile);
    }
}
