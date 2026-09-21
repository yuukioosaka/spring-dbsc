package click.yukio.dbsc.demo;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

/**
 * A sample host application for manual browser testing of the DBSC library.
 *
 * <p>It is built the way a real adopter would build it: an ordinary Spring Boot
 * app with Spring Security form login, whose login success handler calls
 * {@code DbscService#bind}. Nothing here is part of the library JAR.
 *
 * <p>Run it with:
 *
 * <pre>
 * mvn -Pdemo -Dmaven.repo.local=.m2repo spring-boot:run
 * </pre>
 *
 * <p>It listens on <strong>HTTPS only</strong>. DBSC cannot be tested over plain
 * HTTP: the {@code __Host-} cookie prefix requires {@code Secure}, and a binding
 * cookie that travels in cleartext defeats the point of the feature. See
 * {@code README-DEMO.md} for the keystore step.
 */
@SpringBootApplication
@Import(DbscAutoConfiguration.class)
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
