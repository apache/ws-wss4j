/**
 * EchoInteropBindingImpl.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.2beta3 Aug 11, 2004 (10:24:52 IST) WSDL2Java emitter.
 */

package org.apache.trust.secconv.axis.fabrikam.impl;

public class EchoInteropBindingImpl implements org.apache.trust.secconv.axis.fabrikam.impl.EchoPort{
    public void echoMyData(javax.xml.rpc.holders.StringHolder myData) throws java.rmi.RemoteException {
    	System.out.println("My data is " + myData.value);
    }

}
