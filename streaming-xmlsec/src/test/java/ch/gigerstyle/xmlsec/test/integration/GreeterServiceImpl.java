package ch.gigerstyle.xmlsec.test.integration;

import org.apache.hello_world_soap_http.Greeter;
import org.apache.hello_world_soap_http.PingMeFault;

import javax.jws.WebParam;

/**
 * User: giger
 * Date: Oct 22, 2010
 * Time: 7:21:12 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class GreeterServiceImpl implements Greeter {

    public void pingMe() throws PingMeFault {
    }

    public String sayHi() {
        return "Hi";
    }

    public void greetMeOneWay(@WebParam(name = "requestType", targetNamespace = "http://apache.org/hello_world_soap_http/types") String requestType) {
    }

    public String greetMe(@WebParam(name = "requestType", targetNamespace = "http://apache.org/hello_world_soap_http/types") String requestType) {
        return requestType;
    }
}
