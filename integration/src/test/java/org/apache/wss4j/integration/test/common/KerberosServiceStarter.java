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
package org.apache.wss4j.integration.test.common;

import org.apache.commons.io.FileUtils;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.factory.DirectoryServiceFactory;
import org.apache.directory.server.core.factory.PartitionFactory;
import org.apache.directory.server.core.interceptor.Interceptor;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.protocol.shared.transport.UdpTransport;
import org.apache.directory.shared.ldap.entry.DefaultServerEntry;
import org.apache.directory.shared.ldap.ldif.LdifEntry;
import org.apache.directory.shared.ldap.ldif.LdifReader;

import java.io.File;
import java.io.InputStream;
import java.net.DatagramSocket;
import java.security.Provider;
import java.security.Security;
import java.util.List;

public class KerberosServiceStarter {

    /**
     * The used DirectoryService instance
     */
    public static DirectoryService directoryService;

    /**
     * The used KdcServer instance
     */
    public static KdcServer kdcServer;

    private static Provider provider = null;
    private static int providerPos = 2;

    private static final int kdcPort = 23749;

    public static boolean startKerberosServer() throws Exception {
        try {
            DatagramSocket datagramSocket = new DatagramSocket(kdcPort);
            datagramSocket.setReuseAddress(true);
            datagramSocket.close();
        } catch (Exception e) {
            return false;
        }

        //Ok, apache ds doesn't like the bouncy castle provider at position 2
        //Caused by: KrbException: Integrity check on decrypted field failed (31) - Integrity check on decrypted field failed
        Provider[] installedProviders = Security.getProviders();
        for (int i = 0; i < installedProviders.length; i++) {
            Provider installedProvider = installedProviders[i];
            if ("BC".equals(installedProvider.getName())) {
                provider = installedProvider;
                providerPos = i;
                Security.removeProvider("BC");
                break;
            }
        }
        if (provider != null) {
            Security.addProvider(provider);
        }

        DirectoryServiceFactory directoryServiceFactory = DefaultDirectoryServiceFactory.DEFAULT;
        directoryService = directoryServiceFactory.getDirectoryService();
        directoryService.setAccessControlEnabled(false);
        directoryService.setAllowAnonymousAccess(false);
        directoryService.getChangeLog().setEnabled(true);

        List<Interceptor> interceptors = directoryService.getInterceptors();
        interceptors.add(new KeyDerivationInterceptor());
        directoryService.setInterceptors(interceptors);
        directoryServiceFactory.init("defaultDS");

        PartitionFactory partitionFactory = directoryServiceFactory.getPartitionFactory();
        Partition partition = partitionFactory.createPartition("example", "dc=example,dc=com",
                1000, new File(directoryService.getWorkingDirectory(), "example"));

        partitionFactory.addIndex(partition, "objectClass", 1000);
        partitionFactory.addIndex(partition, "dc", 1000);
        partitionFactory.addIndex(partition, "ou", 1000);

        partition.setSchemaManager(directoryService.getSchemaManager());
        // Inject the partition into the DirectoryService
        directoryService.addPartition(partition);

        InputStream is = KerberosServiceStarter.class.getClassLoader().getResourceAsStream("kerberos/kerberos.ldif");
        LdifReader ldifReader = new LdifReader(is);
        for (LdifEntry entry : ldifReader) {
            if (entry.isChangeAdd()) {
                directoryService.getAdminSession().add(new DefaultServerEntry(directoryService.getSchemaManager(), entry.getEntry()));
            } else if (entry.isChangeModify()) {
                directoryService.getAdminSession().modify(entry.getDn(), entry.getModificationItems());
            }
        }
        ldifReader.close();

        kdcServer = new KdcServer();
        kdcServer.setServiceName("DefaultKrbServer");
        kdcServer.setKdcPrincipal("krbtgt/service.ws.apache.org@service.ws.apache.org");
        kdcServer.setPrimaryRealm("service.ws.apache.org");
        kdcServer.setMaximumTicketLifetime(60000 * 1440);
        kdcServer.setMaximumRenewableLifetime(60000 * 10080);
        UdpTransport udp = new UdpTransport("localhost", kdcPort);
        kdcServer.addTransports(udp);
        kdcServer.setEncryptionTypes(new EncryptionType[]{EncryptionType.AES128_CTS_HMAC_SHA1_96});
        kdcServer.setDirectoryService(directoryService);
        kdcServer.start();

        return true;
    }

    public static void stopKerberosServer() throws Exception {
        try {
            directoryService.shutdown();
            FileUtils.deleteDirectory(directoryService.getWorkingDirectory());
            kdcServer.stop();
        } finally {
            //restore BC position
            Security.removeProvider("BC");
            if (provider != null) {
                Security.insertProviderAt(provider, providerPos);
            }
        }
    }
}
