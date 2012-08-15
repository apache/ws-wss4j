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

package org.apache.ws.security.transform;

import java.security.Provider;

/**
 * A provider for the STR Transform.
 */
public class STRTransformProvider extends Provider {

    /**
     * 
     */
    private static final long serialVersionUID = -9148982936620100249L;

    public STRTransformProvider() {
       super("STRTransform", 1.6, "Security Token Reference Transform Provider");
       put(
           (String)"TransformService." + STRTransform.TRANSFORM_URI, 
           "org.apache.ws.security.transform.STRTransform"
       );
       put((String)"TransformService." + STRTransform.TRANSFORM_URI + " MechanismType", "DOM");
   }
}
