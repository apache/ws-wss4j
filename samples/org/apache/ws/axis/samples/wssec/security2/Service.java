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

package org.apache.ws.axis.samples.wssec.security2;

/**
 * Sample Service
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class Service {
    /**
     * Test method that returns a hard-coded string
     * <p/>
     * 
     * @return string
     */
    public String testMethod() {
        return "Hi, you've reached the testMethod.";
    }

    /**
     * Add 2 integers and return the result.
     * 
     * @param x 
     * @param y 
     * @return 
     * @throws Exception 
     */
    public int addInt(int x, int y) throws Exception {
        return x + y;
    }
}
