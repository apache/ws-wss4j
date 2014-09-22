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
package org.apache.wss4j.policy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.wss4j.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.*;

public class AlgorithmSuite extends AbstractSecurityAssertion implements PolicyContainingAssertion {

    protected static final Map<String, AlgorithmSuiteType> algorithmSuiteTypes = new HashMap<String, AlgorithmSuiteType>();

    static {
        algorithmSuiteTypes.put("Basic256", new AlgorithmSuiteType(
                "Basic256",
                SPConstants.SHA1,
                SPConstants.AES256,
                SPConstants.KW_AES256,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L256,
                SPConstants.P_SHA1_L192,
                256, 192, 256, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic192", new AlgorithmSuiteType(
                "Basic192",
                SPConstants.SHA1,
                SPConstants.AES192,
                SPConstants.KW_AES192,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic128", new AlgorithmSuiteType(
                "Basic128",
                SPConstants.SHA1,
                SPConstants.AES128,
                SPConstants.KW_AES128,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L128,
                SPConstants.P_SHA1_L128,
                128, 128, 128, 256, 1024, 4096));
        algorithmSuiteTypes.put("TripleDes", new AlgorithmSuiteType(
                "TripleDes",
                SPConstants.SHA1,
                SPConstants.TRIPLE_DES,
                SPConstants.KW_TRIPLE_DES,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic256Rsa15", new AlgorithmSuiteType(
                "Basic256Rsa15",
                SPConstants.SHA1,
                SPConstants.AES256,
                SPConstants.KW_AES256,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L256,
                SPConstants.P_SHA1_L192,
                256, 192, 256, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic192Rsa15", new AlgorithmSuiteType(
                "Basic192Rsa15",
                SPConstants.SHA1,
                SPConstants.AES192,
                SPConstants.KW_AES192,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic128Rsa15", new AlgorithmSuiteType(
                "Basic128Rsa15",
                SPConstants.SHA1,
                SPConstants.AES128,
                SPConstants.KW_AES128,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L128,
                SPConstants.P_SHA1_L128,
                128, 128, 128, 256, 1024, 4096));
        algorithmSuiteTypes.put("TripleDesRsa15", new AlgorithmSuiteType(
                "TripleDesRsa15",
                SPConstants.SHA1,
                SPConstants.TRIPLE_DES,
                SPConstants.KW_TRIPLE_DES,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic256Sha256", new AlgorithmSuiteType(
                "Basic256Sha256",
                SPConstants.SHA256,
                SPConstants.AES256,
                SPConstants.KW_AES256,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L256,
                SPConstants.P_SHA1_L192,
                256, 256, 256, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic192Sha256", new AlgorithmSuiteType(
                "Basic192Sha256",
                SPConstants.SHA256,
                SPConstants.AES192,
                SPConstants.KW_AES192,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic128Sha256", new AlgorithmSuiteType(
                "Basic128Sha256",
                SPConstants.SHA256,
                SPConstants.AES128,
                SPConstants.KW_AES128,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L128,
                SPConstants.P_SHA1_L128,
                128, 128, 128, 256, 1024, 4096));
        algorithmSuiteTypes.put("TripleDesSha256", new AlgorithmSuiteType(
                "TripleDesSha256",
                SPConstants.SHA256,
                SPConstants.TRIPLE_DES,
                SPConstants.KW_TRIPLE_DES,
                SPConstants.KW_RSA_OAEP,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic256Sha256Rsa15", new AlgorithmSuiteType(
                "Basic256Sha256Rsa15",
                SPConstants.SHA256,
                SPConstants.AES256,
                SPConstants.KW_AES256,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L256,
                SPConstants.P_SHA1_L192,
                256, 192, 256, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic192Sha256Rsa15", new AlgorithmSuiteType(
                "Basic192Sha256Rsa15",
                SPConstants.SHA256,
                SPConstants.AES192,
                SPConstants.KW_AES192,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
        algorithmSuiteTypes.put("Basic128Sha256Rsa15", new AlgorithmSuiteType(
                "Basic128Sha256Rsa15",
                SPConstants.SHA256,
                SPConstants.AES128,
                SPConstants.KW_AES128,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L128,
                SPConstants.P_SHA1_L128,
                128, 128, 128, 256, 1024, 4096));
        algorithmSuiteTypes.put("TripleDesSha256Rsa15", new AlgorithmSuiteType(
                "TripleDesSha256Rsa15",
                SPConstants.SHA256,
                SPConstants.TRIPLE_DES,
                SPConstants.KW_TRIPLE_DES,
                SPConstants.KW_RSA15,
                SPConstants.P_SHA1_L192,
                SPConstants.P_SHA1_L192,
                192, 192, 192, 256, 1024, 4096));
    }

    public static final class AlgorithmSuiteType {

        private String name;
        private String digest;
        private String encryption;
        private String symmetricKeyWrap;
        private String asymmetricKeyWrap;
        private String encryptionKeyDerivation;
        private String signatureKeyDerivation;
        private int encryptionDerivedKeyLength;
        private int signatureDerivedKeyLength;
        private int minimumSymmetricKeyLength;
        private int maximumSymmetricKeyLength;
        private int minimumAsymmetricKeyLength;
        private int maximumAsymmetricKeyLength;
        private String ns;

        public AlgorithmSuiteType(String name, String digest, String encryption, String symmetricKeyWrap, String asymmetricKeyWrap,
                           String encryptionKeyDerivation, String signatureKeyDerivation, int encryptionDerivedKeyLength,
                           int signatureDerivedKeyLength, int minimumSymmetricKeyLength,
                           int maximumSymmetricKeyLength, int minimumAsymmetricKeyLength, int maximumAsymmetricKeyLength) {
            this.name = name;
            this.digest = digest;
            this.encryption = encryption;
            this.symmetricKeyWrap = symmetricKeyWrap;
            this.asymmetricKeyWrap = asymmetricKeyWrap;
            this.encryptionKeyDerivation = encryptionKeyDerivation;
            this.signatureKeyDerivation = signatureKeyDerivation;
            this.encryptionDerivedKeyLength = encryptionDerivedKeyLength;
            this.signatureDerivedKeyLength = signatureDerivedKeyLength;
            this.minimumSymmetricKeyLength = minimumSymmetricKeyLength;
            this.maximumSymmetricKeyLength = maximumSymmetricKeyLength;
            this.minimumAsymmetricKeyLength = minimumAsymmetricKeyLength;
            this.maximumAsymmetricKeyLength = maximumAsymmetricKeyLength;
        }
        
        public AlgorithmSuiteType(AlgorithmSuiteType algorithmSuiteType) {
            this.name = algorithmSuiteType.name;
            this.digest = algorithmSuiteType.digest;
            this.encryption = algorithmSuiteType.encryption;
            this.symmetricKeyWrap = algorithmSuiteType.symmetricKeyWrap;
            this.asymmetricKeyWrap = algorithmSuiteType.asymmetricKeyWrap;
            this.encryptionKeyDerivation = algorithmSuiteType.encryptionKeyDerivation;
            this.signatureKeyDerivation = algorithmSuiteType.signatureKeyDerivation;
            this.encryptionDerivedKeyLength = algorithmSuiteType.encryptionDerivedKeyLength;
            this.signatureDerivedKeyLength = algorithmSuiteType.signatureDerivedKeyLength;
            this.minimumSymmetricKeyLength = algorithmSuiteType.minimumSymmetricKeyLength;
            this.maximumSymmetricKeyLength = algorithmSuiteType.maximumSymmetricKeyLength;
            this.minimumAsymmetricKeyLength = algorithmSuiteType.minimumAsymmetricKeyLength;
            this.maximumAsymmetricKeyLength = algorithmSuiteType.maximumAsymmetricKeyLength;
        }
        
        public String getName() {
            return name;
        }

        public String getDigest() {
            return digest;
        }

        public String getEncryption() {
            return encryption;
        }

        public String getSymmetricKeyWrap() {
            return symmetricKeyWrap;
        }

        public String getAsymmetricKeyWrap() {
            return asymmetricKeyWrap;
        }

        public String getEncryptionKeyDerivation() {
            return encryptionKeyDerivation;
        }

        public String getSignatureKeyDerivation() {
            return signatureKeyDerivation;
        }

        public int getEncryptionDerivedKeyLength() {
            return encryptionDerivedKeyLength;
        }

        public int getSignatureDerivedKeyLength() {
            return signatureDerivedKeyLength;
        }

        public int getMinimumSymmetricKeyLength() {
            return minimumSymmetricKeyLength;
        }

        public int getMaximumSymmetricKeyLength() {
            return maximumSymmetricKeyLength;
        }

        public int getMinimumAsymmetricKeyLength() {
            return minimumAsymmetricKeyLength;
        }

        public int getMaximumAsymmetricKeyLength() {
            return maximumAsymmetricKeyLength;
        }
        
        public void setNamespace(String ns) {
            this.ns = ns;
        }
        
        public String getNamespace() {
            return ns;
        }
    }

    public enum XPathType {
        XPathNone(null),
        XPath10(SPConstants.XPATH),
        XPathFilter20(SPConstants.XPATH20),
        AbsXPath(SPConstants.ABS_XPATH);

        private static final Map<String, XPathType> lookup = new HashMap<String, XPathType>();

        static {
            for (XPathType u : EnumSet.allOf(XPathType.class))
                lookup.put(u.name(), u);
        }

        public static XPathType lookUp(String name) {
            return lookup.get(name);
        }

        private String value;

        public String getValue() {
            return value;
        }

        XPathType(String value) {
            this.value = value;
        }
    }

    public enum C14NType {
        ExclusiveC14N(SPConstants.EX_C14N),
        InclusiveC14N(SPConstants.C14N),
        InclusiveC14N11(SPConstants.C14N11);

        private static final Map<String, C14NType> lookup = new HashMap<String, C14NType>();

        static {
            for (C14NType u : EnumSet.allOf(C14NType.class))
                lookup.put(u.name(), u);
        }

        private String value;

        public static C14NType lookUp(String name) {
            return lookup.get(name);
        }

        public String getValue() {
            return value;
        }

        C14NType(String value) {
            this.value = value;
        }
    }

    public enum SOAPNormType {
        SOAPNormalizationNone(null),
        SOAPNormalization10(SPConstants.SOAP_NORMALIZATION_10);

        private static final Map<String, SOAPNormType> lookup = new HashMap<String, SOAPNormType>();

        static {
            for (SOAPNormType u : EnumSet.allOf(SOAPNormType.class))
                lookup.put(u.name(), u);
        }

        public static SOAPNormType lookUp(String name) {
            return lookup.get(name);
        }

        private String value;

        public String getValue() {
            return value;
        }

        SOAPNormType(String value) {
            this.value = value;
        }
    }

    public enum STRType {
        STRTransformNone(null),
        STRTransform10(SPConstants.STR_TRANSFORM_10);

        private static final Map<String, STRType> lookup = new HashMap<String, STRType>();

        static {
            for (STRType u : EnumSet.allOf(STRType.class))
                lookup.put(u.name(), u);
        }

        public static STRType lookUp(String name) {
            return lookup.get(name);
        }

        private String value;

        public String getValue() {
            return value;
        }

        STRType(String value) {
            this.value = value;
        }
    }

    private Policy nestedPolicy;
    private AlgorithmSuiteType algorithmSuiteType;
    private C14NType c14n = C14NType.ExclusiveC14N;
    private SOAPNormType soapNormType = SOAPNormType.SOAPNormalizationNone;
    private STRType strType = STRType.STRTransformNone;
    private XPathType xPathType = XPathType.XPathNone;

    private String symmetricSignature = SPConstants.HMAC_SHA1;
    private String asymmetricSignature = SPConstants.RSA_SHA1;
    private String computedKey = SPConstants.P_SHA1;

    public AlgorithmSuite(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version);
        this.nestedPolicy = nestedPolicy;

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public Policy getPolicy() {
        return nestedPolicy;
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getAlgorithmSuite();
    }

    @Override
    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, getPolicy());
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new AlgorithmSuite(getVersion(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, AlgorithmSuite algorithmSuite) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (int i = 0; i < assertions.size(); i++) {
                Assertion assertion = assertions.get(i);
                String assertionName = assertion.getName().getLocalPart();
                String assertionNamespace = assertion.getName().getNamespaceURI();
                if (!getVersion().getNamespace().equals(assertionNamespace)) {
                    parseCustomAssertion(assertion);
                    continue;
                }
                AlgorithmSuiteType algorithmSuiteType = algorithmSuiteTypes.get(assertionName);
                if (algorithmSuiteType != null) {
                    if (algorithmSuite.getAlgorithmSuiteType() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    
                    // Clone so as not to change the namespace for other AlgorithmSuiteTypes...
                    AlgorithmSuiteType newAlgorithmSuiteType = new AlgorithmSuiteType(algorithmSuiteType);
                    newAlgorithmSuiteType.setNamespace(getVersion().getNamespace());
                    algorithmSuite.setAlgorithmSuiteType(newAlgorithmSuiteType);
                    continue;
                }
                C14NType c14NType = C14NType.lookUp(assertionName);
                if (c14NType != null) {
                    if (algorithmSuite.getC14n() == C14NType.InclusiveC14N) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    algorithmSuite.setC14n(c14NType);
                    continue;
                }
                SOAPNormType soapNormType = SOAPNormType.lookUp(assertionName);
                if (soapNormType != null) {
                    if (algorithmSuite.getSoapNormType() == SOAPNormType.SOAPNormalization10) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    algorithmSuite.setSoapNormType(soapNormType);
                    continue;
                }
                STRType strType = STRType.lookUp(assertionName);
                if (strType != null) {
                    if (algorithmSuite.getStrType() == STRType.STRTransform10) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    algorithmSuite.setStrType(strType);
                    continue;
                }
                XPathType xPathType = XPathType.lookUp(assertionName);
                if (xPathType != null) {
                    if (algorithmSuite.getXPathType() != XPathType.XPathNone) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    algorithmSuite.setXPathType(xPathType);
                    continue;
                }
            }
        }
    }

    protected void parseCustomAssertion(Assertion assertion) {
    }

    public AlgorithmSuiteType getAlgorithmSuiteType() {
        return algorithmSuiteType;
    }

    protected void setAlgorithmSuiteType(AlgorithmSuiteType algorithmSuiteType) {
        this.algorithmSuiteType = algorithmSuiteType;
    }

    public C14NType getC14n() {
        return c14n;
    }

    protected void setC14n(C14NType c14n) {
        this.c14n = c14n;
    }

    public SOAPNormType getSoapNormType() {
        return soapNormType;
    }

    protected void setSoapNormType(SOAPNormType soapNormType) {
        this.soapNormType = soapNormType;
    }

    public STRType getStrType() {
        return strType;
    }

    protected void setStrType(STRType strType) {
        this.strType = strType;
    }

    public XPathType getXPathType() {
        return xPathType;
    }

    protected void setXPathType(XPathType xPathType) {
        this.xPathType = xPathType;
    }

    public String getAsymmetricSignature() {
        return asymmetricSignature;
    }

    public String getSymmetricSignature() {
        return symmetricSignature;
    }

    public String getComputedKey() {
        return computedKey;
    }
    
    public static Collection<String> getSupportedAlgorithmSuiteNames() {
        return algorithmSuiteTypes.keySet();
    }

    public void setSymmetricSignature(String symmetricSignature) {
        this.symmetricSignature = symmetricSignature;
    }

    public void setAsymmetricSignature(String asymmetricSignature) {
        this.asymmetricSignature = asymmetricSignature;
    }
}

