package com.roarnet.app;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class ParticipantTcpTunnel {

    private static final int MAX_CHUNK = 64 * 1024;
    private static final int MAX_QUEUE = 1024 * 1024;
    private static final int CONNECT_TIMEOUT = 10000;
    private static final int IDLE_TIMEOUT = 60000;

    private static final ConcurrentHashMap<String, Session> SESSIONS =
        new ConcurrentHashMap<>();

    private static final int MAX_FINAL_TRAFFIC_REPORTS = 256;

    private static final Map<String, long[]> FINAL_TRAFFIC_REPORTS =
        new LinkedHashMap<>();

    private ParticipantTcpTunnel() {}

    private static final class Session {
        final Socket socket;
        final InputStream input;
        final OutputStream output;
        final ConcurrentLinkedQueue<byte[]> received =
            new ConcurrentLinkedQueue<>();
        final AtomicInteger queuedBytes = new AtomicInteger(0);
        final AtomicLong bytesSent = new AtomicLong(0);
        final AtomicLong bytesReceived = new AtomicLong(0);
        volatile Thread readerThread;
        volatile boolean closed = false;

        Session(Socket socket) throws IOException {
            this.socket = socket;
            this.input = socket.getInputStream();
            this.output = socket.getOutputStream();
        }
    }

    private static boolean validSessionId(String id) {
        return id != null &&
            id.matches("[A-Za-z0-9_-]{8,100}");
    }

    private static boolean isPublicAddress(InetAddress address) {
        if (address == null ||
            address.isAnyLocalAddress() ||
            address.isLoopbackAddress() ||
            address.isLinkLocalAddress() ||
            address.isSiteLocalAddress() ||
            address.isMulticastAddress()) {
            return false;
        }

        byte[] b = address.getAddress();

        if (b.length == 4) {
            int a = b[0] & 255;
            int c = b[1] & 255;
            int d = b[2] & 255;

            if (a == 0 ||
                a == 10 ||
                a == 127 ||
                a >= 224 ||
                (a == 100 && c >= 64 && c <= 127) ||
                (a == 169 && c == 254) ||
                (a == 172 && c >= 16 && c <= 31) ||
                (a == 192 && c == 0 && d == 0) ||
                (a == 192 && c == 0 && d == 2) ||
                (a == 192 && c == 88 && d == 99) ||
                (a == 192 && c == 168) ||
                (a == 198 && (c == 18 || c == 19)) ||
                (a == 198 && c == 51 && d == 100) ||
                (a == 203 && c == 0 && d == 113) ||
                a >= 240) {
                return false;
            }

            return true;
        }

        if (b.length == 16) {
            int first = b[0] & 255;
            int second = b[1] & 255;
            int third = b[2] & 255;
            int fourth = b[3] & 255;

            // IPv6 global unicast: 2000::/3 only.
            if ((first & 0xE0) != 0x20) {
                return false;
            }

            // Documentation prefix: 2001:db8::/32.
            if (first == 0x20 && second == 0x01 &&
                third == 0x0D && fourth == 0xB8) {
                return false;
            }

            // Special-purpose 2001::/23.
            if (first == 0x20 && second == 0x01 &&
                (third == 0x00 || third == 0x01)) {
                return false;
            }

            // Deprecated 6to4 transition prefix: 2002::/16.
            if (first == 0x20 && second == 0x02) {
                return false;
            }

            // Documentation prefix: 3fff::/20.
            if (first == 0x3F && second == 0xFF &&
                (third & 0xF0) == 0x00) {
                return false;
            }

            return true;
        }

        return false;
    }

    public static synchronized boolean open(
        String sessionId,
        String host,
        int port
    ) throws IOException {

        if (!validSessionId(sessionId) ||
            host == null || host.isEmpty() ||
            host.length() > 253 ||
            port != 80 && port != 443) {
            throw new IOException("DESTINATION_POLICY_REJECTED");
        }

        if (SESSIONS.containsKey(sessionId)) {
            throw new IOException("SESSION_ALREADY_EXISTS");
        }

        InetAddress[] addresses = InetAddress.getAllByName(host);

        if (addresses.length == 0) {
            throw new IOException("DESTINATION_DNS_FAILED");
        }

        for (InetAddress address : addresses) {
            if (!isPublicAddress(address)) {
                throw new IOException("PRIVATE_DESTINATION_BLOCKED");
            }
        }

        IOException lastError = null;

        for (InetAddress address : addresses) {
            Socket socket = new Socket();

            try {
                socket.setTcpNoDelay(true);
                socket.setKeepAlive(true);
                socket.setSoTimeout(IDLE_TIMEOUT);

                socket.connect(
                    new InetSocketAddress(address, port),
                    CONNECT_TIMEOUT
                );

                Session session = new Session(socket);

                if (SESSIONS.putIfAbsent(sessionId, session) != null) {
                    socket.close();
                    throw new IOException("SESSION_ALREADY_EXISTS");
                }

                startReader(sessionId, session);
                return true;

            } catch (IOException error) {
                lastError = error;
                try { socket.close(); } catch (Exception ignored) {}
            }
        }

        throw lastError != null
            ? lastError
            : new IOException("TCP_CONNECT_FAILED");
    }

    private static void startReader(
        String sessionId,
        Session session
    ) {
        Thread reader = new Thread(() -> {
            byte[] buffer = new byte[16 * 1024];

            try {
                while (!session.closed) {
                    int count;

                    try {
                        count = session.input.read(buffer);
                    } catch (SocketTimeoutException timeout) {
                        throw new IOException("TCP_IDLE_TIMEOUT");
                    }

                    if (count < 0) break;
                    if (count == 0) continue;

                    int current = session.queuedBytes.addAndGet(count);

                    if (current > MAX_QUEUE) {
                        session.queuedBytes.addAndGet(-count);
                        throw new IOException("TCP_RECEIVE_QUEUE_LIMIT");
                    }

                    byte[] chunk = new byte[count];
                    System.arraycopy(buffer, 0, chunk, 0, count);
                    session.received.offer(chunk);
                    session.bytesReceived.addAndGet(count);
                }
            } catch (IOException ignored) {
            } finally {
                close(sessionId);
            }
        }, "RoarNet-TCP-Reader");

        session.readerThread = reader;
        reader.setDaemon(true);
        reader.start();
    }

    private static boolean writeToSocket(
        String sessionId,
        byte[] data
    ) throws IOException {

        Session session = SESSIONS.get(sessionId);

        if (session == null || session.closed) {
            throw new IOException("ACTIVE_SESSION_NOT_FOUND");
        }

        if (data == null || data.length == 0 ||
            data.length > MAX_CHUNK) {
            throw new IOException("INVALID_TCP_CHUNK_SIZE");
        }

        synchronized (session.output) {
            if (session.closed || session.socket.isClosed()) {
                throw new IOException("SESSION_CLOSED");
            }

            session.output.write(data);
            session.output.flush();
            session.bytesSent.addAndGet(data.length);
        }

        return true;
    }

    public static boolean send(
        String sessionId,
        byte[] data
    ) throws IOException {
        return writeToSocket(sessionId, data);
    }

    public static List<String> receive(
        String sessionId,
        int maxItems
    ) throws IOException {

        Session session = SESSIONS.get(sessionId);

        if (session == null) {
            throw new IOException("ACTIVE_SESSION_NOT_FOUND");
        }

        int limit = Math.max(1, Math.min(16, maxItems));
        List<String> result = new ArrayList<>();

        for (int i = 0; i < limit; i++) {
            byte[] chunk = session.received.poll();
            if (chunk == null) break;

            session.queuedBytes.addAndGet(-chunk.length);

            result.add(
                android.util.Base64.encodeToString(
                    chunk,
                    android.util.Base64.NO_WRAP
                )
            );
        }

        return result;
    }

    public static boolean write(
        String sessionId,
        byte[] data
    ) throws IOException {
        return writeToSocket(sessionId, data);
    }

    public static long[] getTrafficBytes(String sessionId) {
        Session session = SESSIONS.get(sessionId);
        if (session == null) return null;

        return new long[] {
            session.bytesSent.get(),
            session.bytesReceived.get()
        };
    }

    public static boolean isActive(String sessionId) {
        Session session = SESSIONS.get(sessionId);
        return session != null &&
            !session.closed &&
            session.socket.isConnected() &&
            !session.socket.isClosed();
    }

    public static void close(String sessionId) {
        Session session = SESSIONS.remove(sessionId);
        if (session == null) return;

        synchronized (session.output) {
            session.closed = true;
            try { session.socket.close(); }
            catch (Exception ignored) {}
        }

        Thread reader = session.readerThread;
        boolean interrupted = false;

        if (reader != null && reader != Thread.currentThread()) {
            while (reader.isAlive()) {
                try {
                    reader.join();
                } catch (InterruptedException error) {
                    interrupted = true;
                }
            }
        }

        long sent = session.bytesSent.get();
        long received = session.bytesReceived.get();

        synchronized (FINAL_TRAFFIC_REPORTS) {
            if (!FINAL_TRAFFIC_REPORTS.containsKey(sessionId)) {
                FINAL_TRAFFIC_REPORTS.put(
                    sessionId,
                    new long[] { sent, received, sent + received }
                );
            }

            while (FINAL_TRAFFIC_REPORTS.size() >
                   MAX_FINAL_TRAFFIC_REPORTS) {
                Iterator<String> iterator =
                    FINAL_TRAFFIC_REPORTS.keySet().iterator();

                if (!iterator.hasNext()) break;
                iterator.next();
                iterator.remove();
            }
        }

        session.received.clear();
        session.queuedBytes.set(0);

        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    public static long[] takeFinalTrafficBytes(String sessionId) {
        synchronized (FINAL_TRAFFIC_REPORTS) {
            return FINAL_TRAFFIC_REPORTS.remove(sessionId);
        }
    }

    public static void closeAll() {
        for (String id : SESSIONS.keySet()) {
            close(id);
        }
    }
}
