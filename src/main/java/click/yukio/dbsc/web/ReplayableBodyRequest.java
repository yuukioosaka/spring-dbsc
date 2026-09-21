package click.yukio.dbsc.web;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Replays a buffered request body.
 *
 * <p>A servlet input stream can be read once, but a body-bound proof requires the
 * guard to read the body before the handler does. Buffering the bytes and wrapping
 * the request lets both see identical content.
 *
 * <p>This preserves the original bytes rather than re-serializing the parsed
 * form, which matters: the proof hash is over the exact wire bytes, so any
 * re-encoding would invalidate it.
 */
public final class ReplayableBodyRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    public ReplayableBodyRequest(HttpServletRequest request) throws java.io.IOException {
        this(request, request.getInputStream().readAllBytes());
    }

    public ReplayableBodyRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
    }

    /** The buffered bytes, as the proof hash saw them. */
    public byte[] body() {
        return body;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream stream = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return stream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // Blocking reads only; DBSC routes do not use async reads.
            }

            @Override
            public int read() {
                return stream.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(body), StandardCharsets.UTF_8));
    }

    @Override
    public int getContentLength() {
        return body.length;
    }

    @Override
    public long getContentLengthLong() {
        return body.length;
    }
}
