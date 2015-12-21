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
package org.apache.wss4j.policy;

import javax.xml.namespace.QName;

public class SP13Constants extends SP12Constants {

    private static SP13Constants sp13Constants = null;

    protected SP13Constants() {
        super();
    }

    public static synchronized SP13Constants getInstance() {
        if (sp13Constants == null) {
            sp13Constants = new SP13Constants();
        }
        return sp13Constants;
    }

    public static final String SP_NS = "http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802";
    public static final String SP_PREFIX = "sp13";

    public static final QName CONTENT_SIGNATURE_TRANSFORM = new QName(
            SP13Constants.SP_NS, SPConstants.CONTENT_SIGNATURE_TRANSFORM, SP13Constants.SP_PREFIX);

    public static final QName ATTACHMENT_COMPLETE_SIGNATURE_TRANSFORM = new QName(
            SP13Constants.SP_NS, SPConstants.ATTACHMENT_COMPLETE_SIGNATURE_TRANSFORM, SP13Constants.SP_PREFIX);

    public static final QName XPATH2_EXPR = new QName(
            SP13Constants.SP_NS, SPConstants.XPATH2_EXPR, SP13Constants.SP_PREFIX);

    public static final QName CREATED = new QName(
            SP13Constants.SP_NS, SPConstants.CREATED, SP13Constants.SP_PREFIX);

    public static final QName NONCE = new QName(
            SP13Constants.SP_NS, SPConstants.NONCE, SP13Constants.SP_PREFIX);

    public static final QName SCOPE_POLICY_15 = new QName(
            SP13Constants.SP_NS, SPConstants.SCOPE_POLICY_15, SP13Constants.SP_PREFIX);

    public static final QName MUST_SUPPORT_INTERACTIVE_CHALLENGE = new QName(
            SP13Constants.SP_NS, SPConstants.MUST_SUPPORT_INTERACTIVE_CHALLENGE, SP13Constants.SP_PREFIX);

    @Override
    public QName getContentSignatureTransform() {
        return CONTENT_SIGNATURE_TRANSFORM;
    }

    @Override
    public QName getAttachmentCompleteSignatureTransform() {
        return ATTACHMENT_COMPLETE_SIGNATURE_TRANSFORM;
    }

    @Override
    public QName getXPath2Expression() {
        return XPATH2_EXPR;
    }

    @Override
    public QName getCreated() {
        return CREATED;
    }

    @Override
    public QName getNonce() {
        return NONCE;
    }

    @Override
    public QName getScopePolicy15() {
        return SCOPE_POLICY_15;
    }

    @Override
    public QName getMustSupportInteractiveChallenge() {
        return MUST_SUPPORT_INTERACTIVE_CHALLENGE;
    }
}
