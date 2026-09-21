package click.yukio.dbsc.web;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves the public origin of a request.
 *
 * <p>Getting this wrong is fatal rather than merely cosmetic: when
 * {@code scope.origin} does not match the real origin, Chromium drops the
 * session. Behind a TLS-terminating proxy the server must therefore derive
 * {@code https} from the forwarded protocol instead of trusting the local
 * request scheme.
 */
public final class OriginResolver {

    private static final String[] FORWARDED_PROTO_HEADERS = {
            "X-Forwarded-Proto", "X-Forwarded-Protocol", "Front-End-Https", "X-Url-Scheme"
    };
    private static final String[] FORWARDED_HOST_HEADERS = {
            "X-Forwarded-Host", "X-Original-Host"
    };

    private OriginResolver() {
    }

    /**
     * @param trustForwardedHeaders whether to consult forwarded-protocol/host
     *        headers. Only enable this behind a proxy that overwrites them;
     *        otherwise a client can spoof the advertised origin.
     * @return the origin as {@code scheme://host}, or {@code null} when the host
     *         cannot be determined
     */
    public static String resolve(HttpServletRequest request, boolean trustForwardedHeaders) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();

        if (trustForwardedHeaders) {
            String forwardedProto = firstHeader(request, FORWARDED_PROTO_HEADERS);
            if (forwardedProto != null && !forwardedProto.isBlank()) {
                // A chain may be comma-joined; the first entry is the client-facing one.
                scheme = forwardedProto.split(",")[0].trim();
            }
            String forwardedHost = firstHeader(request, FORWARDED_HOST_HEADERS);
            if (forwardedHost != null && !forwardedHost.isBlank()) {
                String candidate = forwardedHost.split(",")[0].trim();
                int colon = candidate.lastIndexOf(':');
                if (colon > 0 && candidate.indexOf(']') < colon) {
                    try {
                        port = Integer.parseInt(candidate.substring(colon + 1));
                    } catch (NumberFormatException ignored) {
                        // Keep the local port when the forwarded host is malformed.
                    }
                    candidate = candidate.substring(0, colon);
                }
                if (!candidate.isEmpty()) {
                    host = candidate;
                }
            }
        }

        if (host == null || host.isEmpty()) {
            return null;
        }
        boolean defaultPort = ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
        return defaultPort ? scheme + "://" + host : scheme + "://" + host + ":" + port;
    }

    private static String firstHeader(HttpServletRequest request, String[] names) {
        for (String name : names) {
            String value = request.getHeader(name);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
