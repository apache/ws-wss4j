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

/**
 * PingBindingImpl.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.2dev Oct 27, 2003 (02:34:09 EST) WSDL2Java emitter.
 */

package secconv.scenarios.ping.impl;


import javax.xml.rpc.holders.StringHolder;

public class PingBindingImpl
    implements secconv.scenarios.ping.impl.PingPort {
    public void ping(
        secconv.scenarios.ping.impl.TicketType pingTicket,
        StringHolder text)
        throws java.rmi.RemoteException {
    	System.out.println("Recieved :: "+pingTicket.get_value());
    }

}
