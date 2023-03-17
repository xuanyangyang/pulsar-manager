/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.pulsar.manager.zuul;

import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslContext;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.ssl.SSLContexts;
import org.apache.pulsar.common.util.SecurityUtility;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.util.TreeSet;

@Configuration
public class HttpsClientConfiguration {
    @Value("${backend.broker.pulsarAdmin.tlsAllowInsecureConnection:false}")
    private Boolean tlsAllowInsecureConnection;
    @Value("${backend.broker.pulsarAdmin.tlsTrustCertsFilePath:}")
    private String tlsTrustCertsFilePath;
    @Value("${backend.broker.pulsarAdmin.tlsCertificateFilePath:}")
    private String tlsCertificateFilePath;
    @Value("${backend.broker.pulsarAdmin.tlsKeyFilePath:}")
    private String tlsKeyFilePath;
    @Value("${backend.broker.pulsarAdmin.tlsEnableHostnameVerification:false}")
    private Boolean tlsEnableHostnameVerification;

    @Bean
    public CloseableHttpClient httpClient() throws Exception {
        LaxRedirectStrategy customLaxRedirectStrategy = new LaxRedirectStrategy() {
            @Override
            protected boolean isRedirectable(final String method) {
                return true;
            }
        };

        if (StringUtils.isNotBlank(tlsTrustCertsFilePath)) {
            JdkSslContext jdkSslContext = (JdkSslContext) SecurityUtility.createNettySslContextForClient(
                    null,
                    tlsAllowInsecureConnection,
                    tlsTrustCertsFilePath,
                    tlsCertificateFilePath,
                    tlsKeyFilePath,
                    new TreeSet<>(),
                    new TreeSet<>());
            SSLContext sslcontext = jdkSslContext.context();
            HostnameVerifier hostnameVerifier = (s, sslSession) -> {
                // Custom logic to verify host name, tlsHostnameVerifier is false for test
                if (!tlsEnableHostnameVerification) {
                    return true;
                } else {
                    HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
                    return hv.verify(s, sslSession);
                }
            };

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslcontext,
                    hostnameVerifier);

            return HttpClients.custom()
                    .setRedirectStrategy(customLaxRedirectStrategy)
                    .setSSLSocketFactory(sslsf)
                    .build();
        }
        return HttpClients.custom().setRedirectStrategy(customLaxRedirectStrategy).build();
    }
}
