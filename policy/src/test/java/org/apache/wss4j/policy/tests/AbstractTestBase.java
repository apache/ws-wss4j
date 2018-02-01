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
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyBuilder;
import org.apache.wss4j.policy.builders.AlgorithmSuiteBuilder;
import org.apache.wss4j.policy.builders.AsymmetricBindingBuilder;
import org.apache.wss4j.policy.builders.BootstrapPolicyBuilder;
import org.apache.wss4j.policy.builders.ContentEncryptedElementsBuilder;
import org.apache.wss4j.policy.builders.EncryptedElementsBuilder;
import org.apache.wss4j.policy.builders.EncryptedPartsBuilder;
import org.apache.wss4j.policy.builders.EncryptionTokenBuilder;
import org.apache.wss4j.policy.builders.HttpsTokenBuilder;
import org.apache.wss4j.policy.builders.InitiatorEncryptionTokenBuilder;
import org.apache.wss4j.policy.builders.InitiatorSignatureTokenBuilder;
import org.apache.wss4j.policy.builders.InitiatorTokenBuilder;
import org.apache.wss4j.policy.builders.IssuedTokenBuilder;
import org.apache.wss4j.policy.builders.KerberosTokenBuilder;
import org.apache.wss4j.policy.builders.KeyValueTokenBuilder;
import org.apache.wss4j.policy.builders.LayoutBuilder;
import org.apache.wss4j.policy.builders.ProtectionTokenBuilder;
import org.apache.wss4j.policy.builders.RecipientEncryptionTokenBuilder;
import org.apache.wss4j.policy.builders.RecipientSignatureTokenBuilder;
import org.apache.wss4j.policy.builders.RecipientTokenBuilder;
import org.apache.wss4j.policy.builders.RelTokenBuilder;
import org.apache.wss4j.policy.builders.RequiredElementsBuilder;
import org.apache.wss4j.policy.builders.RequiredPartsBuilder;
import org.apache.wss4j.policy.builders.SamlTokenBuilder;
import org.apache.wss4j.policy.builders.SecureConversationTokenBuilder;
import org.apache.wss4j.policy.builders.SecurityContextTokenBuilder;
import org.apache.wss4j.policy.builders.SignatureTokenBuilder;
import org.apache.wss4j.policy.builders.SignedElementsBuilder;
import org.apache.wss4j.policy.builders.SignedPartsBuilder;
import org.apache.wss4j.policy.builders.SpnegoContextTokenBuilder;
import org.apache.wss4j.policy.builders.SupportingTokensBuilder;
import org.apache.wss4j.policy.builders.SymmetricBindingBuilder;
import org.apache.wss4j.policy.builders.TransportBindingBuilder;
import org.apache.wss4j.policy.builders.TransportTokenBuilder;
import org.apache.wss4j.policy.builders.Trust10Builder;
import org.apache.wss4j.policy.builders.Trust13Builder;
import org.apache.wss4j.policy.builders.UsernameTokenBuilder;
import org.apache.wss4j.policy.builders.WSS10Builder;
import org.apache.wss4j.policy.builders.WSS11Builder;
import org.apache.wss4j.policy.builders.X509TokenBuilder;
import org.custommonkey.xmlunit.DetailedDiff;
import org.custommonkey.xmlunit.Diff;
import org.custommonkey.xmlunit.XMLUnit;

public abstract class AbstractTestBase extends org.junit.Assert {
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
        try (InputStreamReader isReader = new InputStreamReader(this.getClass().getClassLoader().getResourceAsStream(classpathResource), StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(isReader);
            StringWriter writer = new StringWriter()) {
            char[] buf = new char[1024];
            int n;
            while ((n = bufferedReader.read(buf)) != -1) {
                writer.write(buf, 0, n);
            }
            writer.close();
            bufferedReader.close();
            return writer.toString();
        }
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
        assertionBuilderFactory.registerBuilder(new BootstrapPolicyBuilder());
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
        return policyBuilder.getPolicy(new ByteArrayInputStream(policy.getBytes(StandardCharsets.UTF_8)));
    }
}
