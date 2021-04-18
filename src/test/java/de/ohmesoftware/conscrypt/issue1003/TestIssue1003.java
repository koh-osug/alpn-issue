package de.ohmesoftware.conscrypt.issue1003;

import lombok.experimental.Delegate;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.conscrypt.Conscrypt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests Conscrypt issue 1003.
 */
public class TestIssue1003 {

    private static void setContextSpi(SSLContext sslContext) {
        try {
            Field contextSpiField = sslContext.getClass().getDeclaredField("contextSpi");
            contextSpiField.setAccessible(true);
            SSLContextSpi sslContextSpi = (SSLContextSpi) contextSpiField.get(sslContext);
            contextSpiField.set(sslContext, new NullAlpnSslContextSpi(sslContextSpi));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static List<SSLEngine> sslEngines = new ArrayList<>();

    private final static class NullAlpnSSLSocketFactory extends SSLSocketFactory {

        private interface Exclude {

            Socket createSocket(Socket socket, String hostname, int port, boolean autoClose);
        }

        @Delegate(types = SSLSocketFactory.class, excludes = Exclude.class)
        private SSLSocketFactory wrappedSSLSocketFactory;

        public NullAlpnSSLSocketFactory(SSLSocketFactory wrappedSSLSocketFactory) {
            this.wrappedSSLSocketFactory = wrappedSSLSocketFactory;
        }

        public Socket createSocket(Socket socket, String hostname, int port, boolean autoClose) throws IOException {
            Socket sslSocket = wrappedSSLSocketFactory.createSocket(socket, hostname, port, autoClose);
            try {
                if (sslSocket.getClass().getName().startsWith("org.conscrypt")) {
                    Field engineField = sslSocket.getClass().getSuperclass().getDeclaredField("engine");
                    engineField.setAccessible(true);
                    SSLEngine engine = (SSLEngine) engineField.get(sslSocket);
                    sslEngines.add(engine);
                }
                return sslSocket;
            } catch (Exception e) {
                return sslSocket;
            }
        }

    }

    private final static class NullAlpnSslContextSpi extends SSLContextSpi {

        private SSLContextSpi wrappedSslContextSpi;

        public NullAlpnSslContextSpi(SSLContextSpi contextSpi) {
            this.wrappedSslContextSpi = contextSpi;
        }

        private Method findMethod(Class<?> startClass, String methodName, Class<?>[] argTypes) {
            Class<?> _class = startClass;
            while (!_class.equals(Object.class)) {
                try {
                    Method method = _class.getDeclaredMethod(methodName, argTypes);
                    method.setAccessible(true);
                    return method;
                } catch (Exception e) {
                    _class = _class.getSuperclass();
                }
            }
            throw new RuntimeException(String.format("Method %s not found.", methodName));
        }

        private <T> T call(String methodName, Class<?>[] argTypes, Object[] args) {
            Method method;
            try {
                method = findMethod(wrappedSslContextSpi.getClass(), methodName, argTypes);
                return (T) method.invoke(wrappedSslContextSpi, args);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
            call("engineInit", new Class[]{KeyManager[].class, TrustManager[].class, SecureRandom.class},
                    new Object[]{km, tm, sr});
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            return new NullAlpnSSLSocketFactory(call("engineGetSocketFactory", new Class[0],
                    new Object[0]));
        }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            return call("engineGetServerSocketFactory", new Class[0],
                    new Object[0]);
        }

        @Override
        protected SSLEngine engineCreateSSLEngine() {
            return call("engineCreateSSLEngine", new Class[0],
                    new Object[0]);
        }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            return call("engineCreateSSLEngine", new Class[]{String.class, int.class},
                    new Object[]{host, port});
        }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            return call("engineGetServerSessionContext", new Class[0],
                    new Object[0]);
        }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            return call("engineGetClientSessionContext", new Class[0],
                    new Object[0]);
        }
    }

    private static OkHttpClient simpleConscrypt() throws Exception {
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.callTimeout(30, TimeUnit.SECONDS);
            builder.connectTimeout(30, TimeUnit.SECONDS);
            builder.readTimeout(30, TimeUnit.SECONDS);
            builder.writeTimeout(30, TimeUnit.SECONDS);
            try {
                Provider jsseProvider = Conscrypt.newProvider();
                TrustManagerFactory defaultTrustManagerFactory = TrustManagerFactory.getInstance("PKIX");
                defaultTrustManagerFactory.init((KeyStore) null);
                SSLContext sslContext = SSLContext.getInstance("TLSv1.3", jsseProvider);
                setContextSpi(sslContext);
                sslContext.init(null, null, new SecureRandom());
                SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) defaultTrustManagerFactory.getTrustManagers()[0]);
            } catch (Exception e) {
                throw new RuntimeException("Could not set-up TLS.", e);
            }
            return builder.build();
        } finally {
            Security.removeProvider(Conscrypt.newProvider().getName());
        }
    }

    @BeforeEach
    private void setUp() {
        sslEngines.clear();
    }

    @Test
    public void testNoAlpn() throws Exception {
        OkHttpClient client = simpleConscrypt();
        Request request = new Request.Builder()
                .url("https://www.spiegel.de")
                .build();
        Response response = client.newCall(request).execute();
        System.out.println(response.body().string());

        SSLEngine engine = sslEngines.get(0);
        Method method = engine.getClass().getDeclaredMethod("getApplicationProtocol");
        method.setAccessible(true);
        String protocol = (String) method.invoke(engine);
        assertEquals("", protocol);
    }

    @Test
    public void testAlpn() throws Exception {
        OkHttpClient client = simpleConscrypt();
        Request request = new Request.Builder()
                .url("https://tools.keycdn.com/http2-test")
                .build();
        Response response = client.newCall(request).execute();
        System.out.println(response.body().string());

        SSLEngine engine = sslEngines.get(0);
        Method method = engine.getClass().getDeclaredMethod("getApplicationProtocol");
        method.setAccessible(true);
        String protocol = (String) method.invoke(engine);
        assertEquals("h2", protocol);
    }
    
}
