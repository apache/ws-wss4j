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

package secconv.scenarios.ping;

import java.net.MalformedURLException;
import java.net.URL;

import javax.xml.rpc.ServiceException;
import javax.xml.rpc.holders.StringHolder;

import org.apache.axis.utils.Options;
import secconv.scenarios.ping.impl.PingPort;
import secconv.scenarios.ping.impl.PingServiceLocator;

/**
 * @author Dimuthu
 *
 */
public class WSConvScenario1 {

    private static final java.lang.String address =
        "http://localhost:9080/axis/services/WSConvScenario1";

    public static void main(String[] args) throws Exception {

        Options opts = new Options(args);
        opts.setDefaultURL(address);
        PingServiceLocator service = new PingServiceLocator();

        URL endpoint;

        try {
            endpoint = new URL(opts.getURL());
        } catch (MalformedURLException e) {
            throw new ServiceException(e);
        }

        PingPort port = (PingPort) service.getWSConvScenario1(endpoint);

        /*
         *    Performin several calls to show  secure conversaton.
         */

        StringHolder text =
            new StringHolder("SecureConversation - The first call");
        for (int i = 0; i < 6; i++) {
            text.value = "SecureConversation - Call number " + i;
            port.ping(
                new secconv.scenarios.ping.impl.TicketType("SecureZoneType"),
                text);
            System.out.println(text.value + " is sucessful.");
        }
    }

}
