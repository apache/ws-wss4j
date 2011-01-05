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

package org.apache.ws.security.saml.ext.builder;

import org.apache.ws.security.saml.ext.OpenSAMLUtil;
import org.apache.ws.security.saml.ext.bean.ActionBean;
import org.apache.ws.security.saml.ext.bean.AttributeBean;
import org.apache.ws.security.saml.ext.bean.AttributeStatementBean;
import org.apache.ws.security.saml.ext.bean.AuthDecisionStatementBean;
import org.apache.ws.security.saml.ext.bean.AuthenticationStatementBean;
import org.apache.ws.security.saml.ext.bean.ConditionsBean;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.apache.ws.security.util.UUIDGenerator;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;

import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;

import java.util.ArrayList;
import java.util.List;


/**
 * Class SAML2ComponentBuilder provides builder methods that can be used
 * to construct SAML v2.0 statements using the OpenSaml library.
 * <p/>
 * Created on May 18, 2009
 */
public class SAML2ComponentBuilder {
    private static SAMLObjectBuilder<Assertion> assertionBuilder;
    
    private static SAMLObjectBuilder<Issuer> issuerBuilder;
    
    private static SAMLObjectBuilder<Subject> subjectBuilder;
    
    private static SAMLObjectBuilder<NameID> nameIdBuilder;
    
    private static SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;
    
    private static SAMLObjectBuilder<Conditions> conditionsBuilder;
    
    private static SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder;
    
    private static SAMLObjectBuilder<AuthnStatement> authnStatementBuilder;
    
    private static SAMLObjectBuilder<AuthnContext> authnContextBuilder;
    
    private static SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder;
    
    private static SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder;
    
    private static SAMLObjectBuilder<Attribute> attributeBuilder;
    
    private static XSStringBuilder stringBuilder;
    
    private static SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder;
    
    private static SAMLObjectBuilder<Audience> audienceBuilder;
    
    private static SAMLObjectBuilder<AuthzDecisionStatement> authorizationDecisionStatementBuilder;
    
    private static SAMLObjectBuilder<Action> actionElementBuilder;
    
    private static XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    /**
     * Create a SAML 2 assertion
     *
     * @return a SAML 2 assertion
     */
    public static Assertion createAssertion() {
        if (assertionBuilder == null) {
            assertionBuilder = (SAMLObjectBuilder<Assertion>) 
                builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
            if (assertionBuilder == null) {
                throw new IllegalStateException(
                    "OpenSaml engine not initialized. Please make sure to initialize the OpenSaml engine "
                    + "prior using it"
                );
            }
        }
        Assertion assertion = 
            assertionBuilder.buildObject(Assertion.DEFAULT_ELEMENT_NAME, Assertion.TYPE_NAME);
        assertion.setID(UUIDGenerator.getUUID());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssueInstant(new DateTime());
        return assertion;
    }

    /**
     * Create an Issuer object
     *
     * @param issuerValue of type String
     * @return an Issuer object
     */
    public static Issuer createIssuer(String issuerValue) {
        if (issuerBuilder == null) {
            issuerBuilder = (SAMLObjectBuilder<Issuer>) 
                builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
            
        }
        Issuer issuer = issuerBuilder.buildObject();
        //
        // The SAML authority that is making the claim(s) in the assertion. The issuer SHOULD 
        // be unambiguous to the intended relying parties.
        issuer.setValue(issuerValue);
        return issuer;
    }

    /**
     * Create a Conditions object
     *
     * @param conditionsBean A ConditionsBean object
     * @return a Conditions object
     */
    public static Conditions createConditions(ConditionsBean conditionsBean) {
        if (conditionsBuilder == null) {
            conditionsBuilder = (SAMLObjectBuilder<Conditions>) 
                builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        }
        
        Conditions conditions = conditionsBuilder.buildObject();
        
        if (conditionsBean == null) {
            DateTime newNotBefore = new DateTime();
            conditions.setNotBefore(newNotBefore);
            conditions.setNotOnOrAfter(newNotBefore.plusMinutes(5));
            return conditions;
        }
        
        int tokenPeriodMinutes = conditionsBean.getTokenPeriodMinutes();
        DateTime notBefore = conditionsBean.getNotBefore();
        DateTime notAfter = conditionsBean.getNotAfter();
        
        if (notBefore != null && notAfter != null) {
            OpenSAMLUtil.validateConditions(notBefore, notAfter);
            conditions.setNotBefore(notBefore);
            conditions.setNotOnOrAfter(notAfter);
        } else {
            DateTime newNotBefore = new DateTime();
            conditions.setNotBefore(newNotBefore);
            conditions.setNotOnOrAfter(newNotBefore.plusMinutes(tokenPeriodMinutes));
        }
        return conditions;
    }

    /**
     * Create an AudienceRestriction object
     *
     * @param audienceURI of type String
     * @return an AudienceRestriction object
     */
    public static AudienceRestriction createAudienceRestriction(String audienceURI) {
        if (audienceRestrictionBuilder == null) {
            audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) 
                builderFactory.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        }
        if (audienceBuilder == null) {
            audienceBuilder = (SAMLObjectBuilder<Audience>) 
                builderFactory.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        }
       
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(audienceURI);
        audienceRestriction.getAudiences().add(audience);
        return audienceRestriction;
    }

    /**
     * Create a Subject.
     *
     * @param nameID of type NameID
     * @param subjectConfirmation of type SubjectConfirmation
     * @return a Subject
     */
    public static Subject createSubject(NameID nameID, SubjectConfirmation subjectConfirmation) {
        if (subjectBuilder == null) {
            subjectBuilder = (SAMLObjectBuilder<Subject>) 
                builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        }
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameID);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        return subject;
    }

    /**
     * Create SAML 2 Authentication Statement(s).
     *
     * @param authBeans A list of AuthenticationStatementBean instances
     * @return SAML 2 Authentication Statement(s).
     */
    public static List<AuthnStatement> createAuthnStatement(
        List<AuthenticationStatementBean> authBeans
    ) {
        List<AuthnStatement> authnStatements = new ArrayList<AuthnStatement>();
        
        if (authnStatementBuilder == null) {
            authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) 
                builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        }
        if (authnContextBuilder == null) {
            authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) 
                builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        }
        if (authnContextClassRefBuilder == null) {
            authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) 
                builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        }
        

        if (authBeans != null && authBeans.size() > 0) {
            for (AuthenticationStatementBean statementBean : authBeans) {
                AuthnStatement authnStatement = authnStatementBuilder.buildObject();
                authnStatement.setAuthnInstant(statementBean.getAuthenticationInstant());
                //authnStatement.setSessionIndex("b07b804c-7c29-ea16-7300-4f3d6f7928ac");
                
                AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
                authnContextClassRef.setAuthnContextClassRef(
                    transformAuthenticationMethod(statementBean.getAuthenticationMethod())
                );
                AuthnContext authnContext = authnContextBuilder.buildObject();
                authnContext.setAuthnContextClassRef(authnContextClassRef);
                authnStatement.setAuthnContext(authnContext);

                authnStatements.add(authnStatement);
            }
        }

        return authnStatements;
    }

    /**
     * Transform the user-supplied authentication method value into one of the supported 
     * specification-compliant values.
     * NOTE: Only "Password" is supported at this time.
     *
     * @param sourceMethod of type String
     * @return String
     */
    private static String transformAuthenticationMethod(String sourceMethod) {
        String transformedMethod = "";

        if ("Password".equalsIgnoreCase(sourceMethod)) {
            transformedMethod = SAML2Constants.AUTH_CONTEXT_CLASS_REF_PASSWORD;
        }

        return transformedMethod;
    }

    /**
     * Create a SAML2 Attribute
     *
     * @param friendlyName of type String
     * @param name         of type String
     * @param values       of type ArrayList
     * @return a SAML2 Attribute
     */
    public static Attribute createAttribute(String friendlyName, String name, List<String> values) {
        if (stringBuilder == null) {
            stringBuilder = (XSStringBuilder)builderFactory.getBuilder(XSString.TYPE_NAME);
        }
        Attribute attribute = createAttribute(friendlyName, name);
        for (String value : values) {
            XSString attributeValue = 
                stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
            attributeValue.setValue(value);
            attribute.getAttributeValues().add(attributeValue);
        }

        return attribute;
    }

    /**
     * Create a SubjectConfirmationData object
     *
     * @param inResponseTo of type String
     * @param recipient    of type String
     * @param notOnOrAfter of type DateTime
     * @return a SubjectConfirmationData object
     */
    public static SubjectConfirmationData createSubjectConfirmationData(
        String inResponseTo, 
        String recipient, 
        DateTime notOnOrAfter
    ) {
        if (subjectConfirmationDataBuilder == null) {
            subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) 
                builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        }
        SubjectConfirmationData subjectConfirmationData = 
            subjectConfirmationDataBuilder.buildObject();
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setRecipient(recipient);
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
        return subjectConfirmationData;
    }

    /**
     * Create a SubjectConfirmation object
     * One of the following subject confirmation methods MUST be used:
     *   urn:oasis:names:tc:SAML:2.0:cm:holder-of-key
     *   urn:oasis:names:tc:SAML:2.0:cm:sender-vouches
     *   urn:oasis:names:tc:SAML:2.0:cm:bearer
     *
     * @param method of type String
     * @return a SubjectConfirmation object
     */
    public static SubjectConfirmation createSubjectConfirmation(String method) {
        if (subjectConfirmationBuilder == null) {
            subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) 
                builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        }
        
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(method);
        return subjectConfirmation;
    }

    /**
     * Create a NameID object
     * One of the following formats MUST be used:
     *   urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
     *   urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
     *   urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName
     *   urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName
     *   urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos
     *   urn:oasis:names:tc:SAML:2.0:nameid-format:entity
     *   urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
     *   urn:oasis:names:tc:SAML:2.0:nameid-format:transient
     *
     * @param subject A SubjectBean instance
     * @return NameID
     */
    public static NameID createNameID(SubjectBean subject) {
        if (nameIdBuilder == null) {
            nameIdBuilder = (SAMLObjectBuilder<NameID>) 
                builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        }
        NameID nameID = nameIdBuilder.buildObject();
        nameID.setNameQualifier(subject.getSubjectNameQualifier());
        nameID.setFormat(NameID.UNSPECIFIED);
        nameID.setValue(subject.getSubjectName());
        return nameID;
    }


    /**
     * Create SAML2 Attribute Statement(s)
     *
     * @param attributeData A list of AttributeStatementBean instances
     * @return SAML2 Attribute Statement(s)
     */
    public static List<AttributeStatement> createAttributeStatement(
        List<AttributeStatementBean> attributeData
    ) {
        List<AttributeStatement> attributeStatements = new ArrayList<AttributeStatement>();
        if (attributeStatementBuilder == null) {
            attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) 
            builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        }

        if (attributeData != null && attributeData.size() > 0) {
            for (AttributeStatementBean statementBean : attributeData) {
                AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
                for (AttributeBean values : statementBean.getSamlAttributes()) {
                    Attribute samlAttribute = 
                        createAttribute(
                            values.getSimpleName(), 
                            values.getQualifiedName(),
                            values.getAttributeValues()
                        );
                    attributeStatement.getAttributes().add(samlAttribute);
                }
                // Add the completed attribute statementBean to the collection
                attributeStatements.add(attributeStatement);
            }
        }

        return attributeStatements;
    }

    /**
     * Create an Attribute object. The name format is of type:
     *   urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified
     *   urn:oasis:names:tc:SAML:2.0:attrname-format:uri
     *   urn:oasis:names:tc:SAML:2.0:attrname-format:basic
     *
     * @param friendlyName of type String
     * @param name of type String
     * @return an Attribute object
     */
    public static Attribute createAttribute(String friendlyName, String name) {
        if (attributeBuilder == null) {
            attributeBuilder = (SAMLObjectBuilder<Attribute>)
                builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        }
        
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setFriendlyName(friendlyName);
        attribute.setNameFormat(SAML2Constants.ATTRNAME_FORMAT_URI);
        attribute.setName(name);
        return attribute;
    }

    /**
     * Create SAML2 AuthorizationDecisionStatement(s)
     *
     * @param decisionData A list of AuthDecisionStatementBean instances
     * @return SAML2 AuthorizationDecisionStatement(s)
     */
    public static List<AuthzDecisionStatement> createAuthorizationDecisionStatement(
        List<AuthDecisionStatementBean> decisionData
    ) {
        List<AuthzDecisionStatement> authDecisionStatements = new ArrayList();
        if (authorizationDecisionStatementBuilder == null) {
            authorizationDecisionStatementBuilder = 
                (SAMLObjectBuilder<AuthzDecisionStatement>)
                    builderFactory.getBuilder(AuthzDecisionStatement.DEFAULT_ELEMENT_NAME);
        }

        if (decisionData != null && decisionData.size() > 0) {
            for (AuthDecisionStatementBean decisionStatementBean : decisionData) {
                AuthzDecisionStatement authDecision = 
                    authorizationDecisionStatementBuilder.buildObject();
                authDecision.setResource(decisionStatementBean.getResource());
                authDecision.setDecision(
                    transformDecisionType(decisionStatementBean.getDecision())
                );

                for (ActionBean actionBean : decisionStatementBean.getActions()) {
                    Action actionElement = createSamlAction(actionBean);
                    authDecision.getActions().add(actionElement);
                }
                authDecisionStatements.add(authDecision);
            }
        }

        return authDecisionStatements;
    }


    /**
     * Create an Action object
     *
     * @param actionBean An ActionBean instance
     * @return an Action object
     */
    public static Action createSamlAction(ActionBean actionBean) {
        if (actionElementBuilder == null) {
            actionElementBuilder = (SAMLObjectBuilder<Action>)
                builderFactory.getBuilder(Action.DEFAULT_ELEMENT_NAME);
        }
        Action actionElement = actionElementBuilder.buildObject();
        actionElement.setNamespace(actionBean.getActionNamespace());
        actionElement.setAction(actionBean.getContents());

        return actionElement;
    }

    /**
     * Create a DecisionTypeEnumeration object
     *
     * @param decision of type Decision
     * @return a DecisionTypeEnumeration object 
     */
    private static DecisionTypeEnumeration transformDecisionType(
        AuthDecisionStatementBean.Decision decision
    ) {
        DecisionTypeEnumeration decisionTypeEnum = DecisionTypeEnumeration.DENY;
        if (decision.equals(AuthDecisionStatementBean.Decision.PERMIT)) {
            decisionTypeEnum = DecisionTypeEnumeration.PERMIT;
        } else if (decision.equals(AuthDecisionStatementBean.Decision.INDETERMINATE)) {
            decisionTypeEnum = DecisionTypeEnumeration.INDETERMINATE;
        }

        return decisionTypeEnum;
    }

}
