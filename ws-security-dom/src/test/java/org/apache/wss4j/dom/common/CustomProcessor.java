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

package org.apache.wss4j.dom.common;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.wss4j.dom.WSConstants;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.dom.engine.WSSecurityEngineResult;

/**
 * a custom processor that inserts itself into the results list
 */
public class CustomProcessor implements Processor {

    public final java.util.List<WSSecurityEngineResult>
    handleToken(
        final org.w3c.dom.Element elem,
        final RequestData data
    ) throws WSSecurityException {
        final WSSecurityEngineResult result =
            new WSSecurityEngineResult(WSConstants.UT_SIGN);
        result.put("foo", this);
        return java.util.Collections.singletonList(result);
    }

    @Override
    public QName[] getQNames() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getQNames'");
    }

    

}
