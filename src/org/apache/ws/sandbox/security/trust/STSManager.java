/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.ws.security.trust;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.issue.STIssuer;
import org.apache.ws.security.trust.message.Info.RequestInfo;
import org.apache.ws.security.trust.renew.STRenewer;
import org.apache.ws.security.trust.validate.STValidator;
import org.w3c.dom.Document;

import java.util.Hashtable;

/**
 * @author Malinda Kaushalye
 *         <p/>
 *         <p/>
 *         The main objective of <code>STSManager</code> is to work as a
 *         decision making component in the server side.
 *         It decides to whom this request must be handed over,
 *         and to carry out the task it uses one <code>RequestResolver</code>
 *         and one <code>RequestInfo</code>  object. This analogous to the real
 *         world the Manager, Clerk and the Report scenario,
 *         where (STS)Manager orders clerk(<code>RequestResolver</code> )
 *         to resolve a certain request and handover a
 *         report (<code>RequestInfo</code> ) about the request.
 *         Depending on the RequestInfo <code>STSManager</code>
 *         decides the worker class. The worker class can be
 *         an Issuer, Validator or a Renewer. Each STS must
 *         define its Issuer, Validator and Renewer class names
 *         in the server-config.wsdd file. <code>STSServerHandler</code>  will
 *         read it and give to the <code>STSManager</code> as a hash table.
 *         <code>STSManager</code> will load the appropriate worker class and give the
 *         response and request documents for further processing.
 */
public class STSManager {
    static Log log = LogFactory.getLog(STSManager.class.getName());
    //Following worker classes are defined in the server-config.wsdd
    String issuerClassName = null;
    String renewerClassName = null;
    String validatorClassName = null;
    //To keep the class name of the worker (issuer, renewer or validater)
    String requestType = "";
    String tokenType = "";
    Hashtable hashOps;

    /**
     * @param hashOps set of parameters coming from STSServerHandler.
     */
    public STSManager(Hashtable hashOps) {
        this.hashOps = hashOps;
    }

    /**
     * Handle the request and build the Response Envelope
     * <p/>
     * <p/>
     * <p/>
     * Handle the request and build the Response Envelope
     *
     * @param req request message envelop as a DOM Document
     * @param res response message envelop as a DOM Document
     * @return modified response message envelop as a DOM Document
     *         Note :
     *         (may not need to use since response message envelop is passed as a reference)
     */
    public Document handleRequest(Document req, Document res)
            throws WSTrustException {

        RequestResolver requestResolver = new RequestResolver(req);

        try {
            log.debug("STS Manager resolving the request");
            RequestInfo requestInfo = requestResolver.resolve();
            this.requestType = requestInfo.getRequestType();            
            //this.tokenType = requestInfo.getTokenType();//we may need to have <wsp:Applies> to override the <wst:TokenType>
            log.debug("STS Manager resolving completed");
        } catch (WSSecurityException wsEx) {

            //wsEx.printStackTrace();
            throw new WSTrustException("STSManager: cannot resolve the request: ",
                    wsEx);
        }
        /********************************************************************
         * Issue
         */
        if (this.requestType.equals(TrustConstants.ISSUE_SECURITY_TOKEN)) {
            //issue    
            
            //get the woker class name
            
            this.issuerClassName = (String) hashOps.get(TrustConstants.ISSUER_CLASS);
            log.debug("Issuer class" + this.issuerClassName);
            
            //Create the instance of the issue/renew/validate class  
            Class wClass = null;
            try {
                wClass = java.lang.Class.forName(issuerClassName);
            } catch (ClassNotFoundException e) {
                throw new WSTrustException("STSManager: cannot load security token class: ",
                        e);
            }
            STIssuer stissuer = null;
            try {
                //Create a new instance of the STIssuer
                stissuer = (STIssuer) wClass.newInstance();

            } catch (java.lang.Exception e) {
                throw new WSTrustException("STSManager: cannot create instance of security token issuer: "
                        + stissuer,
                        e);
            }

            try {
                res = stissuer.issue(req, res);

            } catch (java.lang.Exception e) {
                throw new WSTrustException("STSManager: could not issue a token " + stissuer,
                        e);
            }

            /********************************************************************
             * Renew
             */
        } else if (this.requestType.equals(TrustConstants.RENEW_SECURITY_TOKEN)) { //renew    
            //                    get the woker class name
            this.renewerClassName = (String) hashOps.get(TrustConstants.RENEWER_CLASS);
            log.debug("renewer  class" + this.renewerClassName);
            //Create the instance of the issue/renew/validate class  
            Class wClass = null;
            try {
                wClass = java.lang.Class.forName(renewerClassName);
            } catch (ClassNotFoundException e) {
                throw new WSTrustException("STSManager: cannot load security token class: ",
                        e);
            }
            STRenewer stRenewer = null;
            try {
                //Create a new instance of the STIssuer
                stRenewer = (STRenewer) wClass.newInstance();

            } catch (java.lang.Exception e) {
                throw new WSTrustException("STSManager: cannot create instance of security token renewer: "
                        + stRenewer,
                        e);
            }

            try {
                res = stRenewer.renew(req, res);

            } catch (java.lang.Exception e) {
                throw new WSTrustException("STSManager: could not renew the token " + stRenewer,
                        e);
            }
            /********************************************************************
             * validate
             */
        } else if (
                this.requestType.equals(TrustConstants.VALIDATE_SECURITY_TOKEN)) { //validate    
//                    get the woker class name
            this.validatorClassName = (String) hashOps.get(TrustConstants.VALIDATOR_CLASS);
            log.debug("validatorClassName " + this.validatorClassName);
            //Create the instance of the issue/renew/validate class  
            Class wClass = null;
            try {
                wClass = java.lang.Class.forName(validatorClassName);
            } catch (ClassNotFoundException e) {
                throw new WSTrustException("STSManager: cannot load security token class: ",
                        e);
            }
            STValidator stValidator = null;
            try {
                //Create a new instance of the STIssuer
                stValidator = (STValidator) wClass.newInstance();

            } catch (java.lang.Exception e) {
                throw new WSTrustException("STSManager: cannot create instance of security token validator: "
                        + stValidator,
                        e);
            }
            try {

                res = stValidator.validate(req, res);

            } catch (java.lang.Exception e) {
                throw new WSTrustException("STSManager: could not validate the token " + stValidator,
                        e);
            }
        } else {
            throw new WSTrustException("STSManager: Cannot Identify the Request Type ");

        }
        return res;
    }

}
