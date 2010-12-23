/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package ch.gigerstyle.xmlsec.test.integration;

import org.apache.hello_world_soap_http.Greeter;
import org.apache.hello_world_soap_http.PingMeFault;

import javax.jws.WebParam;
import javax.jws.WebService;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
@WebService(targetNamespace = "http://apache.org/hello_world_soap_http", serviceName = "SOAPService", endpointInterface = "org.apache.hello_world_soap_http.Greeter")
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
