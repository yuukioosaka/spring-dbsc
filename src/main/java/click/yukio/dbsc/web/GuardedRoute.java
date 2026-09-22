package click.yukio.dbsc.web;

/**
 * Declares that a request path requires a DBSC-protected session, for
 * {@link DbscGuardFilter}.
 *
 * <p>Declare one bean per guarded route and the auto-configuration collects them:
 *
 * <pre>{@code
 * @Bean
 * GuardedRoute transferRoute() {
 *     return GuardedRoute.at("/api/transfer");
 * }
 * }</pre>
 *
 * <p>Declaring none is the default, and leaves the guard filter a no-op: DBSC
 * protects nothing until the application says which requests matter.
 *
 * <p>A route declared here is matched exactly, by {@code getRequestURI()}, the same
 * way the protocol routes are. That is deliberate — a guarded route should be a
 * route you can point at, not a pattern whose coverage has to be reasoned about.
 * Prefix matching is what a filter-chain security matcher is for, and putting a
 * second interpretation of paths here would be a surprise.
 *
 * @param path the request path to guard, matched exactly
 */
public record GuardedRoute(String path) {

    public GuardedRoute {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("a guarded route needs a path");
        }
        if (!path.startsWith("/")) {
            throw new IllegalArgumentException("a guarded route path must start with '/': " + path);
        }
    }

    /** Guards {@code path}. */
    public static GuardedRoute at(String path) {
        return new GuardedRoute(path);
    }
}
