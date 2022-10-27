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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
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

@Warmup(iterations = 4, time = 4)
@Measurement(iterations = 4, time = 4)
@Fork(value = 1)
public class TransportLayerSecurityBenchmark {

    private static final String[] PROTOCOLS = new String[] {"TLSv1.3"};

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public final void sslSocketTransfer(BenchmarkState state, Blackhole blackhole) throws IOException {
        try (SSLSocket socket = (SSLSocket) state.socketFactory.createSocket()) {
            socket.setEnabledProtocols(PROTOCOLS);
            socket.setEnabledCipherSuites(new String[] {state.cipher});
            socket.setTcpNoDelay(true);
            socket.connect(state.serverAddress);
            try (InputStream is = socket.getInputStream()) {
                is.transferTo(new BlackholeOutputStream(blackhole));
            }
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

        private SSLServerSocket serverSocket;
        private ExecutorService executor;

        private SSLSocketFactory socketFactory;

        // Standard Size 8KiB buffer matching InputStream.DEFAULT_BUFFER_SIZE
        private final byte[] data = new byte[8 * 1024];

        private SocketAddress serverAddress;

        private final AtomicBoolean done = new AtomicBoolean();

        @Setup
        @SuppressWarnings("DnsLookup")
        public void setup() throws Exception {
            ThreadLocalRandom.current().nextBytes(data);
            executor = Executors.newCachedThreadPool();
            SSLContext context = sslContext(true);
            SSLServerSocketFactory factory = context.getServerSocketFactory();
            serverSocket = (SSLServerSocket) factory.createServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.setEnabledProtocols(PROTOCOLS);
            serverSocket.setEnabledCipherSuites(new String[] {cipher});
            serverSocket.bind(null);
            serverAddress = new InetSocketAddress("127.0.0.1", serverSocket.getLocalPort());
            accept();
            socketFactory = sslContext(false).getSocketFactory();
        }

        private void accept() {
            executor.execute(() -> {
                while (!done.get()) {
                    try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                        try (OutputStream outputStream = socket.getOutputStream()) {
                            for (int i = 0; i < length; i += data.length) {
                                outputStream.write(data, 0, Math.min(length - i, data.length));
                            }
                        }
                    } catch (Throwable t) {
                        if (done.get()) {
                            return;
                        }
                        t.printStackTrace();
                        RuntimeException thrown = new RuntimeException(t);
                        try {
                            tearDown();
                        } catch (Throwable tt) {
                            thrown.addSuppressed(tt);
                        }
                        throw thrown;
                    }
                }
            });
        }

        @TearDown
        public void tearDown() throws Exception {
            if (!done.getAndSet(true)) {
                executor.shutdownNow();
                serverSocket.close();
                int seconds = 3;
                if (!executor.awaitTermination(seconds, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Executor failed ot shut down within " + seconds + "s");
                }
            }
        }
    }

    private static SSLContext sslContext(boolean server) {
        try {
            KeyManager[] keyManagers = new KeyManager[0];
            if (server) {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                try (InputStream stream =
                        TransportLayerSecurityBenchmark.class.getClassLoader().getResourceAsStream("keyStore.jks")) {
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
            try (InputStream stream =
                    TransportLayerSecurityBenchmark.class.getClassLoader().getResourceAsStream("trustStore.jks")) {
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
                        .include(TransportLayerSecurityBenchmark.class.getSimpleName())
                        .addProfiler(GCProfiler.class)
                        .build())
                .run();
    }
}
