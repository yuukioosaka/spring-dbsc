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
 *
 * <p>A configured override ({@code dbsc.scope-origin}) wins outright, before
 * forwarded headers are consulted. That is the escape hatch for a deployment where
 * neither the local request nor the forwarded headers describe the public origin
 * correctly — a proxy that rewrites the host to an internal name, a CDN that sets
 * no header this class knows, or a test that must pin one origin. It is validated
 * once at startup ({@link #validateConfigured}), not per request.
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
        return resolve(request, trustForwardedHeaders, null);
    }

    /**
     * Resolves the public origin, honouring a configured override.
     *
     * @param configuredOrigin a fixed origin that wins over everything the request
     *        says, or {@code null}/blank to derive it. Already validated by
     *        {@link #validateConfigured}, so it is returned as given
     * @return the origin as {@code scheme://host}, or {@code null} when the host
     *         cannot be determined
     */
    public static String resolve(
            HttpServletRequest request, boolean trustForwardedHeaders, String configuredOrigin) {
        if (configuredOrigin != null && !configuredOrigin.isBlank()) {
            return configuredOrigin;
        }

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

    /**
     * Checks a configured origin at startup rather than letting it fail per request.
     *
     * <p>A wrong value here does not produce an error anywhere: the server answers 200
     * to every registration, and Chromium quietly discards the session, because §8.9
     * requires {@code origin} to be same-site with the destination and terminates on a
     * mismatch. Failing the context start turns that into a startup error.
     *
     * @throws IllegalArgumentException when the value is not an absolute
     *         {@code scheme://host[:port]} origin, when the scheme is neither
     *         {@code http} nor {@code https}, when a path, query or fragment is
     *         present, or on a non-numeric or out-of-range port
     */
    public static void validateConfigured(String configuredOrigin) {
        if (configuredOrigin == null || configuredOrigin.isBlank()) {
            return;
        }
        String value = configuredOrigin.trim();
        if (!value.equals(configuredOrigin)) {
            throw new IllegalArgumentException(
                    "scopeOrigin must not have leading or trailing whitespace: \"" + configuredOrigin + "\"");
        }
        int schemeEnd = value.indexOf("://");
        if (schemeEnd < 0) {
            throw new IllegalArgumentException(
                    "scopeOrigin must be an absolute origin like \"https://example.com\": got \"" + value + "\"");
        }
        String scheme = value.substring(0, schemeEnd);
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IllegalArgumentException(
                    "scopeOrigin scheme must be http or https: got \"" + scheme + "\"");
        }
        String authority = value.substring(schemeEnd + 3);
        if (authority.isEmpty()) {
            throw new IllegalArgumentException("scopeOrigin has no host: \"" + value + "\"");
        }
        if (authority.indexOf('/') >= 0 || authority.indexOf('?') >= 0 || authority.indexOf('#') >= 0) {
            throw new IllegalArgumentException(
                    "scopeOrigin must not carry a path, query or fragment: \"" + value + "\"");
        }
        if (authority.endsWith(":")) {
            throw new IllegalArgumentException("scopeOrigin has an empty port: \"" + value + "\"");
        }
        int colon = authority.lastIndexOf(':');
        // A colon inside a bracketed IPv6 literal is part of the host, not a port.
        if (colon > 0 && authority.indexOf(']') < colon) {
            String port = authority.substring(colon + 1);
            int parsed;
            try {
                parsed = Integer.parseInt(port);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        "scopeOrigin port is not a number: \"" + port + "\" in \"" + value + "\"");
            }
            if (parsed < 1 || parsed > 65535) {
                throw new IllegalArgumentException(
                        "scopeOrigin port is out of range (1-65535): " + parsed);
            }
        }
    }
}
