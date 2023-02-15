/*
 * (c) Copyright 2022 Palantir Technologies Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.palantir.java.crypto.allocations;

import io.undertow.Undertow;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.util.Headers;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.KeyStore;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.xnio.Options;
import org.xnio.Sequence;

@Warmup(iterations = 4, time = 4)
@Measurement(iterations = 4, time = 4)
@Fork(value = 1)
public class DirectBufferTransportLayerSecurityBenchmark {

    private static final String[] PROTOCOLS = new String[] {"TLSv1.3"};

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public final void download(BenchmarkState state, Blackhole blackhole) throws IOException {
        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://localhost:" + state.port).openConnection();
        conn.setSSLSocketFactory(state.socketFactory);
        int code = conn.getResponseCode();
        if (code != 200) {
            throw new RuntimeException("not ok: " + code);
        }
        try (InputStream is = conn.getInputStream()) {
            is.transferTo(new BlackholeOutputStream(blackhole));
        }
    }

    @State(Scope.Benchmark)
    @SuppressWarnings({
        "DesignForExtension",
        "StringSplitter",
        "checkstyle:VisibilityModifier",
        "checkstyle:RegexpSinglelineJava"
    })
    public static class BenchmarkState {

        @Param({"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"})
        public String cipher;

        @Param("104857600") // 100 MiB
        public int length;

        @Param
        public SecurityProviderParam provider;

        private SSLSocketFactory socketFactory;

        // Standard Size 8KiB buffer matching InputStream.DEFAULT_BUFFER_SIZE
        private final byte[] data = new byte[8 * 1024];

        private int port;

        private Undertow server;

        @Setup
        @SuppressWarnings("DnsLookup")
        public void setup() throws Exception {
            provider.install();
            ThreadLocalRandom.current().nextBytes(data);
            socketFactory = sslContext(false).getSocketFactory();
            server = Undertow.builder()
                    .setDirectBuffers(true)
                    .addHttpsListener(0, "0.0.0.0", sslContext(true))
                    .setSocketOption(Options.SSL_ENABLED_PROTOCOLS, Sequence.of(PROTOCOLS))
                    .setSocketOption(Options.SSL_ENABLED_CIPHER_SUITES, Sequence.of(cipher))
                    .setWorkerThreads(32)
                    .setIoThreads(2)
                    .setHandler(new BlockingHandler(exchange -> {
                        exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, Integer.toString(length));
                        try (OutputStream outputStream = exchange.getOutputStream()) {
                            for (int i = 0; i < length; i += data.length) {
                                outputStream.write(data, 0, Math.min(length - i, data.length));
                            }
                        }
                    }))
                    .build();
            server.start();
            port = ((InetSocketAddress) server.getListenerInfo().get(0).getAddress()).getPort();
        }

        @TearDown
        public void tearDown() throws Exception {
            Undertow maybe = server;
            if (maybe != null) {
                maybe.stop();
            }
        }
    }

    private static SSLContext sslContext(boolean server) {
        try {
            KeyManager[] keyManagers = new KeyManager[0];
            if (server) {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                try (InputStream stream = DirectBufferTransportLayerSecurityBenchmark.class
                        .getClassLoader()
                        .getResourceAsStream("keyStore.jks")) {
                    if (stream == null) {
                        throw new IllegalStateException();
                    }
                    keyStore.load(stream, "keystore".toCharArray());
                }
                KeyManagerFactory keyManagerFactory =
                        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, "keystore".toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream stream = DirectBufferTransportLayerSecurityBenchmark.class
                    .getClassLoader()
                    .getResourceAsStream("trustStore.jks")) {
                if (stream == null) {
                    throw new IllegalStateException();
                }
                trustStore.load(stream, null);
            }
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            sslContext.init(keyManagers, trustManagers, null);
            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] _args) throws RunnerException {
        new Runner(new OptionsBuilder()
                        .include(DirectBufferTransportLayerSecurityBenchmark.class.getSimpleName())
                        .addProfiler(GCProfiler.class)
                        .build())
                .run();
    }
}
