package click.yukio.dbsc.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * The requests whose session must currently be DBSC-protected, for
 * {@link DbscGuardFilter}.
 *
 * <p>Declare one bean and the auto-configuration collects it. Patterns are ordinary
 * Spring Security {@link RequestMatcher}s, so the whole ecosystem applies — an
 * {@code AntPathRequestMatcher("/api/**")} covers a prefix, and a custom matcher can
 * decide on a header or a tenant:
 *
 * <pre>{@code
 * @Bean
 * DbscGuardRoutes dbscGuardRoutes() {
 *     return DbscGuardRoutes.of(
 *             new AntPathRequestMatcher("/api/**"),
 *             new AntPathRequestMatcher("/account/**"));
 * }
 * }</pre>
 *
 * <p>Declaring none is the default and leaves the guard filter a no-op: DBSC protects
 * nothing until the application says which requests matter.
 *
 * <p><strong>This is the range, not the policy.</strong> What happens to a request
 * inside the range is decided by {@link click.yukio.dbsc.DbscService#guardDecision}:
 * a client that never registered is allowed through, a session that registered and
 * then lapsed is refused. That is why a matcher covering every route is a reasonable
 * thing to write, and why a client without DBSC support does not need to be excluded
 * from it.
 *
 * <p>This type is itself a {@link RequestMatcher} and matches when <em>any</em> of
 * the supplied matchers does, so it composes with {@code AndRequestMatcher} and
 * friends, and a test can substitute a lambda.
 */
public final class DbscGuardRoutes implements RequestMatcher {

    private final RequestMatcher delegate;

    private DbscGuardRoutes(RequestMatcher delegate) {
        this.delegate = delegate;
    }

    /**
     * Guards the requests matched by any of {@code matchers}.
     *
     * @throws IllegalArgumentException when no matcher is supplied — an empty set is
     *         almost always a wiring mistake, and it would silently disable the guard
     * @throws NullPointerException when a matcher is null
     */
    public static DbscGuardRoutes of(RequestMatcher... matchers) {
        if (matchers == null || matchers.length == 0) {
            throw new IllegalArgumentException(
                    "DbscGuardRoutes.of needs at least one RequestMatcher; "
                            + "listing none would leave the guard a silent no-op");
        }
        Arrays.stream(matchers).forEach(m -> Objects.requireNonNull(m, "matcher"));
        return new DbscGuardRoutes(matchers.length == 1 ? matchers[0] : new OrRequestMatcher(matchers));
    }

    /**
     * Guards the requests matched by any of {@code matchers}. Use this overload when
     * the matchers are assembled dynamically.
     */
    public static DbscGuardRoutes of(List<? extends RequestMatcher> matchers) {
        Objects.requireNonNull(matchers, "matchers");
        return of(matchers.toArray(RequestMatcher[]::new));
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return delegate.matches(request);
    }
}
