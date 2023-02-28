package com.github.mc1arke.aws.hsm.mutualtls;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Optional;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.amazonaws.cloudhsm.jce.jni.exception.ProviderInitializationException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;

public class MutualTlsExample {

    public static void main(String... args) throws IOException, GeneralSecurityException, ProviderInitializationException {
        // Create the HSM provider and add it to the JCE's list
        CloudHsmProvider provider = new CloudHsmProvider();
        // perform any additional steps here, such as authenticating the provider to the HSM
        Security.addProvider(provider);

        // load the keystore - AWS CloudHSM with no backing files (i.e. the key is on the HSM)
        KeyStore hsmKeyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE);
        hsmKeyStore.load(null, null);

        // load the system truststore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(System.getProperty("java.home") + "/lib/security/cacerts")) {
            trustStore.load(inputStream, "changeit".toCharArray());
        }

        // link the certificates to the keys so that we can perform mutual TLS - the HSM can't store certificates
        // and the JVM needs to know what key to use for verification operations once it has selected a certificate
        // which means the 2 items need to be linked in the keystore
        try (InputStream inputStream = MutualTlsExample.class.getResourceAsStream("/badssl-cert.pem")) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certificateFactory.generateCertificate(inputStream);

            // the alias needs to be the one we imported the Bad SSL key into the HSM as
            Key badSslKey = hsmKeyStore.getKey("badssl", null);

            // put the key and cert chain in the keystore. The key is just a handle to the actual key on the HSM at
            // this point, so any attempt to use this key will defer to the HSM JCE provider and offload the operation
            // onto the HSM
            hsmKeyStore.setKeyEntry("badssl", badSslKey, null, new Certificate[]{certificate});
        }

        // create an SSL context that's aware of the BadSSL client cert/key for authentication, and backed by our truststore
        SSLContext sslContext = SSLContexts.custom()
            .loadKeyMaterial(hsmKeyStore, null, ((aliases, socket) -> Optional.of("badssl")
                .filter(aliases::containsKey)
                .orElse(null)))
            .loadTrustMaterial(trustStore, null)
            .build();

        // create a registry that uses our SSL context for HTTPS connections
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
            .register(URIScheme.HTTP.id, PlainConnectionSocketFactory.getSocketFactory())
            .register(URIScheme.HTTPS.id, new SSLConnectionSocketFactory(sslContext))
            .build();

        // and a client that uses our registry
        HttpClient httpClient = HttpClients.custom()
            .disableAutomaticRetries()
            .setConnectionManager(new BasicHttpClientConnectionManager(registry))
            .build();

        // and finally a rest template that uses the client
        RestTemplate restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));

        // now use the client. In 'real-world', this call would happen thousands of times per active HSM session
        for (int i = 0; i < 10; i++) {
            ResponseEntity<String> responseEntity = restTemplate.getForEntity("https://client.badssl.com", String.class);
            if (!responseEntity.getStatusCode().is2xxSuccessful()) {
                throw new IllegalStateException("Non-success HTTP status received for request");
            }
            System.out.println(responseEntity.getBody());
        }
    }

}
