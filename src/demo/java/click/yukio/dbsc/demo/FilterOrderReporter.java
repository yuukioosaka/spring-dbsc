package click.yukio.dbsc.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

/**
 * Prints the DBSC relevant part of Spring Security's filter order at startup.
 *
 * <p>Filter ordering bugs are invisible at runtime — the failure looks like an
 * unrelated 403 from whichever filter happened to run first. Dumping the actual
 * order makes them obvious.
 */
@Component
class FilterOrderReporter {

    private static final Logger log = LoggerFactory.getLogger(FilterOrderReporter.class);

    private final FilterChainProxy proxy;

    FilterOrderReporter(FilterChainProxy proxy) {
        this.proxy = proxy;
    }

    @EventListener(ApplicationReadyEvent.class)
    void report() {
        int chainIndex = 0;
        for (SecurityFilterChain chain : proxy.getFilterChains()) {
            log.info("--- security chain #{} ({}) ---", chainIndex++, chain.getClass().getSimpleName());
            int i = 0;
            for (var filter : chain.getFilters()) {
                log.info("  {}. {}", i++, filter.getClass().getSimpleName());
            }
        }
    }
}
