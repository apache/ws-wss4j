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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.util.List;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import junit.framework.TestCase;

import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyBuilder;
import org.apache.wss4j.policy.builders.*;
import org.custommonkey.xmlunit.DetailedDiff;
import org.custommonkey.xmlunit.Diff;
import org.custommonkey.xmlunit.XMLUnit;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractTestBase extends TestCase {
    protected XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();

    protected String serializePolicy(Policy policy) throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLStreamWriter xmlStreamWriter = xmlOutputFactory.createXMLStreamWriter(stringWriter);
        policy.serialize(xmlStreamWriter);
        xmlStreamWriter.close();
        stringWriter.close();
        return stringWriter.toString();
    }

    protected void assertXMLisEqual(String actual, String expected) throws Exception {
        XMLUnit.setIgnoreWhitespace(true);
        final Diff diff = new Diff(expected, actual);
        DetailedDiff myDiff = new DetailedDiff(diff);
        List<?> allDifferences = myDiff.getAllDifferences();
        assertEquals(myDiff.toString(), 0, allDifferences.size());
    }

    protected String loadPolicyFile(String classpathResource) throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(this.getClass().getClassLoader().getResourceAsStream(classpathResource), "UTF-8"));
        StringWriter writer = new StringWriter();
        char[] buf = new char[1024];
        int n;
        while ((n = bufferedReader.read(buf)) != -1) {
            writer.write(buf, 0, n);
        }
        writer.close();
        bufferedReader.close();
        return writer.toString();
    }

    protected Policy loadPolicy(String policy) throws Exception {
        PolicyBuilder policyBuilder = new PolicyBuilder();

        AssertionBuilderFactory assertionBuilderFactory = policyBuilder.getAssertionBuilderFactory();
        assertionBuilderFactory.registerBuilder(new AlgorithmSuiteBuilder());
        assertionBuilderFactory.registerBuilder(new AsymmetricBindingBuilder());
        assertionBuilderFactory.registerBuilder(new ContentEncryptedElementsBuilder());
        assertionBuilderFactory.registerBuilder(new EncryptedElementsBuilder());
        assertionBuilderFactory.registerBuilder(new EncryptedPartsBuilder());
        assertionBuilderFactory.registerBuilder(new EncryptionTokenBuilder());
        assertionBuilderFactory.registerBuilder(new HttpsTokenBuilder());
        assertionBuilderFactory.registerBuilder(new InitiatorEncryptionTokenBuilder());
        assertionBuilderFactory.registerBuilder(new InitiatorSignatureTokenBuilder());
        assertionBuilderFactory.registerBuilder(new InitiatorTokenBuilder());
        assertionBuilderFactory.registerBuilder(new IssuedTokenBuilder());
        assertionBuilderFactory.registerBuilder(new KerberosTokenBuilder());
        assertionBuilderFactory.registerBuilder(new KeyValueTokenBuilder());
        assertionBuilderFactory.registerBuilder(new LayoutBuilder());
        assertionBuilderFactory.registerBuilder(new ProtectionTokenBuilder());
        assertionBuilderFactory.registerBuilder(new RecipientEncryptionTokenBuilder());
        assertionBuilderFactory.registerBuilder(new RecipientSignatureTokenBuilder());
        assertionBuilderFactory.registerBuilder(new RecipientTokenBuilder());
        assertionBuilderFactory.registerBuilder(new RelTokenBuilder());
        assertionBuilderFactory.registerBuilder(new RequiredElementsBuilder());
        assertionBuilderFactory.registerBuilder(new RequiredPartsBuilder());
        assertionBuilderFactory.registerBuilder(new SamlTokenBuilder());
        assertionBuilderFactory.registerBuilder(new SecureConversationTokenBuilder());
        assertionBuilderFactory.registerBuilder(new SecurityContextTokenBuilder());
        assertionBuilderFactory.registerBuilder(new SignatureTokenBuilder());
        assertionBuilderFactory.registerBuilder(new SignedElementsBuilder());
        assertionBuilderFactory.registerBuilder(new SignedPartsBuilder());
        assertionBuilderFactory.registerBuilder(new SpnegoContextTokenBuilder());
        assertionBuilderFactory.registerBuilder(new SupportingTokensBuilder());
        assertionBuilderFactory.registerBuilder(new SymmetricBindingBuilder());
        assertionBuilderFactory.registerBuilder(new TransportBindingBuilder());
        assertionBuilderFactory.registerBuilder(new TransportTokenBuilder());
        assertionBuilderFactory.registerBuilder(new Trust10Builder());
        assertionBuilderFactory.registerBuilder(new Trust13Builder());
        assertionBuilderFactory.registerBuilder(new UsernameTokenBuilder());
        assertionBuilderFactory.registerBuilder(new WSS10Builder());
        assertionBuilderFactory.registerBuilder(new WSS11Builder());
        assertionBuilderFactory.registerBuilder(new X509TokenBuilder());

        return loadPolicy(policy, policyBuilder);
    }
    
    protected Policy loadPolicy(String policy, PolicyBuilder policyBuilder) throws Exception {
        return policyBuilder.getPolicy(new ByteArrayInputStream(policy.getBytes("UTF-8")));
    }
}
