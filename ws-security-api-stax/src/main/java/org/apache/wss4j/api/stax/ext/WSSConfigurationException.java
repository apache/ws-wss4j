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
package org.apache.wss4j.api.stax.ext;

import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * Exception when configuration errors are detected
 */
public class WSSConfigurationException extends WSSecurityException {

    private static final long serialVersionUID = 689628294822027113L;

    public WSSConfigurationException(ErrorCode errorCode, Exception exception, String msgId, Object[] args) {
        super(errorCode, exception, msgId, args);
    }

    public WSSConfigurationException(ErrorCode errorCode, Exception exception, String msgId) {
        super(errorCode, exception, msgId);
    }

    public WSSConfigurationException(ErrorCode errorCode, String msgId, Object[] args) {
        super(errorCode, msgId, args);
    }

    public WSSConfigurationException(ErrorCode errorCode, String msgId) {
        super(errorCode, msgId);
    }

    public WSSConfigurationException(ErrorCode errorCode) {
        super(errorCode);
    }
}
