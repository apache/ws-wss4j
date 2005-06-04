/**
 * PingServiceLocator.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.2 May 03, 2005 (02:20:24 EDT) WSDL2Java emitter.
 */

package secconv.scenarios.ping.impl;

public class PingServiceLocator extends org.apache.axis.client.Service implements secconv.scenarios.ping.impl.PingService {

    public PingServiceLocator() {
    }


    public PingServiceLocator(org.apache.axis.EngineConfiguration config) {
        super(config);
    }

    public PingServiceLocator(java.lang.String wsdlLoc, javax.xml.namespace.QName sName) throws javax.xml.rpc.ServiceException {
        super(wsdlLoc, sName);
    }

    // Use to get a proxy class for WSConvScenario1
    private java.lang.String WSConvScenario1_address = "http://localhost:9080/pingservice/WSConvScenario1";

    public java.lang.String getWSConvScenario1Address() {
        return WSConvScenario1_address;
    }

    // The WSDD service name defaults to the port name.
    private java.lang.String WSConvScenario1WSDDServiceName = "WSConvScenario1";

    public java.lang.String getWSConvScenario1WSDDServiceName() {
        return WSConvScenario1WSDDServiceName;
    }

    public void setWSConvScenario1WSDDServiceName(java.lang.String name) {
        WSConvScenario1WSDDServiceName = name;
    }

    public secconv.scenarios.ping.impl.PingPort getWSConvScenario1() throws javax.xml.rpc.ServiceException {
       java.net.URL endpoint;
        try {
            endpoint = new java.net.URL(WSConvScenario1_address);
        }
        catch (java.net.MalformedURLException e) {
            throw new javax.xml.rpc.ServiceException(e);
        }
        return getWSConvScenario1(endpoint);
    }

    public secconv.scenarios.ping.impl.PingPort getWSConvScenario1(java.net.URL portAddress) throws javax.xml.rpc.ServiceException {
        try {
            secconv.scenarios.ping.impl.PingBindingStub _stub = new secconv.scenarios.ping.impl.PingBindingStub(portAddress, this);
            _stub.setPortName(getWSConvScenario1WSDDServiceName());
            return _stub;
        }
        catch (org.apache.axis.AxisFault e) {
            return null;
        }
    }

    public void setWSConvScenario1EndpointAddress(java.lang.String address) {
        WSConvScenario1_address = address;
    }

    /**
     * For the given interface, get the stub implementation.
     * If this service has no port for the given interface,
     * then ServiceException is thrown.
     */
    public java.rmi.Remote getPort(Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
        try {
            if (secconv.scenarios.ping.impl.PingPort.class.isAssignableFrom(serviceEndpointInterface)) {
                secconv.scenarios.ping.impl.PingBindingStub _stub = new secconv.scenarios.ping.impl.PingBindingStub(new java.net.URL(WSConvScenario1_address), this);
                _stub.setPortName(getWSConvScenario1WSDDServiceName());
                return _stub;
            }
        }
        catch (java.lang.Throwable t) {
            throw new javax.xml.rpc.ServiceException(t);
        }
        throw new javax.xml.rpc.ServiceException("There is no stub implementation for the interface:  " + (serviceEndpointInterface == null ? "null" : serviceEndpointInterface.getName()));
    }

    /**
     * For the given interface, get the stub implementation.
     * If this service has no port for the given interface,
     * then ServiceException is thrown.
     */
    public java.rmi.Remote getPort(javax.xml.namespace.QName portName, Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
        if (portName == null) {
            return getPort(serviceEndpointInterface);
        }
        java.lang.String inputPortName = portName.getLocalPart();
        if ("WSConvScenario1".equals(inputPortName)) {
            return getWSConvScenario1();
        }
        else  {
            java.rmi.Remote _stub = getPort(serviceEndpointInterface);
            ((org.apache.axis.client.Stub) _stub).setPortName(portName);
            return _stub;
        }
    }

    public javax.xml.namespace.QName getServiceName() {
        return new javax.xml.namespace.QName("http://xmlsoap.org/Ping", "PingService");
    }

    private java.util.HashSet ports = null;

    public java.util.Iterator getPorts() {
        if (ports == null) {
            ports = new java.util.HashSet();
            ports.add(new javax.xml.namespace.QName("http://xmlsoap.org/Ping", "WSConvScenario1"));
        }
        return ports.iterator();
    }

    /**
    * Set the endpoint address for the specified port name.
    */
    public void setEndpointAddress(java.lang.String portName, java.lang.String address) throws javax.xml.rpc.ServiceException {
        if ("WSConvScenario1".equals(portName)) {
            setWSConvScenario1EndpointAddress(address);
        }
        else { // Unknown Port Name
            throw new javax.xml.rpc.ServiceException(" Cannot set Endpoint Address for Unknown Port" + portName);
        }
    }

    /**
    * Set the endpoint address for the specified port name.
    */
    public void setEndpointAddress(javax.xml.namespace.QName portName, java.lang.String address) throws javax.xml.rpc.ServiceException {
        setEndpointAddress(portName.getLocalPart(), address);
    }

}
