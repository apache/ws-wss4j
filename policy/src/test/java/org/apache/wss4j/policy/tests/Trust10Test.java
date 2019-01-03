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
package org.apache.wss4j.policy.tests;

import org.apache.neethi.*;
import org.apache.wss4j.policy.SP11Constants;
import org.apache.wss4j.policy.model.Trust10;
import org.junit.Test;

import java.util.Iterator;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class Trust10Test extends AbstractTestBase {

    @Test
    public void testTrust10_11() throws Exception {
        String fileName = "Trust10.xml";
        String policyFile = loadPolicyFile("policy/model/sp11/" + fileName);
        String serializedPolicyReferenceFile = loadPolicyFile("policy/model/sp11/serialized/" + fileName);
        String normalizedPolicyReferenceFile = loadPolicyFile("policy/model/sp11/normalized/" + fileName);
        Policy policy = loadPolicy(policyFile);
        String serializedPolicy = serializePolicy(policy);
        assertXMLisEqual(serializedPolicy, serializedPolicyReferenceFile);

        Iterator<List<Assertion>> alternativeIterator = policy.getAlternatives();
        int count = 0;
        while (alternativeIterator.hasNext()) {
            List<Assertion> alternative = alternativeIterator.next();
            assertEquals(1, alternative.size());
            assertTrue(alternative.get(0) instanceof Trust10);
            Trust10 trust10 = (Trust10) alternative.get(0);
            assertFalse(trust10.isNormalized());
            assertTrue(trust10.isIgnorable());
            assertTrue(trust10.isOptional());
            assertEquals(Constants.TYPE_ASSERTION, trust10.getType());
            assertEquals(SP11Constants.TRUST_10, trust10.getName());
            assertTrue(trust10.isMustSupportClientChallenge());
            assertTrue(trust10.isMustSupportServerChallenge());
            assertTrue(trust10.isRequireClientEntropy());
            assertTrue(trust10.isRequireServerEntropy());
            assertTrue(trust10.isMustSupportIssuedTokens());
            count++;
        }
        assertEquals(1, count);

        policy = policy.normalize(true);
        serializedPolicy = serializePolicy(policy);
        assertXMLisEqual(serializedPolicy, normalizedPolicyReferenceFile);

        alternativeIterator = policy.getAlternatives();
        List<Assertion> alternative = alternativeIterator.next();
        assertEquals(0, alternative.size());

        List<PolicyComponent> policyComponents = policy.getPolicyComponents();
        assertEquals(1, policyComponents.size());
        PolicyOperator policyOperator = (PolicyOperator) policyComponents.get(0);
        policyComponents = policyOperator.getPolicyComponents();
        assertEquals(2, policyComponents.size());
        All all = (All) policyComponents.get(0);
        List<PolicyComponent> policyComponentsAll = all.getAssertions();
        assertEquals(0, policyComponentsAll.size());

        all = (All) policyComponents.get(1);
        policyComponentsAll = all.getAssertions();
        assertEquals(1, policyComponentsAll.size());

        Iterator<PolicyComponent> policyComponentIterator = policyComponentsAll.iterator();
        Trust10 trust13 = (Trust10) policyComponentIterator.next();
        assertTrue(trust13.isNormalized());
        assertTrue(trust13.isIgnorable());
        assertFalse(trust13.isOptional());
        assertEquals(Constants.TYPE_ASSERTION, trust13.getType());
        assertEquals(SP11Constants.TRUST_10, trust13.getName());
        assertTrue(trust13.isMustSupportClientChallenge());
        assertTrue(trust13.isMustSupportServerChallenge());
        assertTrue(trust13.isRequireClientEntropy());
        assertTrue(trust13.isRequireServerEntropy());
        assertTrue(trust13.isMustSupportIssuedTokens());
    }
}