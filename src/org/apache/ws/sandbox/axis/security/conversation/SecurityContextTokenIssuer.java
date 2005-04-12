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
package org.apache.ws.axis.security.conversation;

import org.apache.axis.message.addressing.EndpointReference;
import org.apache.ws.security.policy.message.token.AppliesTo;
import org.apache.ws.security.trust.issue.STIssuer;
import org.apache.ws.security.trust.message.token.LifeTime;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Ruchith Fernando
 */
public class SecurityContextTokenIssuer implements STIssuer {

    /* (non-Javadoc)
     * @see org.apache.ws.security.trust.issue.STIssuer#issue(org.w3c.dom.Document, org.w3c.dom.Document)
     */
    public Document issue(Document req, Document res) throws Exception {
        
        //Create an instance of the WSDoAllReceiver and get the request cleanedup :-)
        
        //
        
        
        Element elemAppliesTo = (Element)WSSecurityUtil.findElement(req,AppliesTo.TOKEN.getLocalPart(),AppliesTo.TOKEN.getNamespaceURI()); 
        Element elemEpr = (Element)elemAppliesTo.getFirstChild();
        EndpointReference epr = new EndpointReference(elemEpr);


        //Create the Lifetime element for the response message
        LifeTime lt = new LifeTime(res,12*60);
        Element elemLifeTime = lt.getElement();

        
        
        
        //Add the SecurityContextToken to the derivedKeyCallbackhandler
        
        return null;
    }

}
