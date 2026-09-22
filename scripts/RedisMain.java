import redis.embedded.RedisServer;

/**
 * Runs a real Redis server for manual testing of the redis-demo profile.
 *
 * <p>This lives in {@code scripts/} rather than {@code src/test} on purpose: it is a
 * development convenience, not a test, and putting it under {@code src/test} would make
 * surefire try to run it. The binary comes from the test-scoped {@code embedded-redis}
 * dependency, which is why {@code run-redis.sh} builds the test classpath.
 *
 * <p>Usage: {@code sh scripts/run-redis.sh [port]}
 */
public class RedisMain {

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 6379;
        RedisServer server = RedisServer.newRedisServer().port(port).build();
        server.start();
        System.out.println("REDIS-UP on " + port + " (Ctrl-C to stop)");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                server.stop();
            } catch (Exception ignored) {
                // Stopping a server that is already gone is not worth reporting.
            }
        }));
        Thread.currentThread().join();
    }
}
