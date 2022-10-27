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

import java.io.OutputStream;
import org.openjdk.jmh.infra.Blackhole;

/**
 * Simple {@link OutputStream} which wraps the {@link Blackhole}.
 */
final class BlackholeOutputStream extends OutputStream {

    private final Blackhole blackhole;

    BlackholeOutputStream(Blackhole blackhole) {
        this.blackhole = blackhole;
    }

    @Override
    public void write(byte[] buf) {
        blackhole.consume(buf);
    }

    @Override
    public void write(byte[] buf, int off, int len) {
        Blackhole snapshot = this.blackhole;
        snapshot.consume(buf);
        snapshot.consume(off);
        snapshot.consume(len);
    }

    @Override
    public void write(int singleByte) {
        blackhole.consume(singleByte);
    }
}
