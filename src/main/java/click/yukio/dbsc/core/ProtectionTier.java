package click.yukio.dbsc.core;

/**
 * Binding strength of a session. Mirrors the toolkit's {@code ProtectionTier}.
 *
 * <ul>
 *   <li>{@code DBSC} - a native hardware-backed key is registered (02).</li>
 *   <li>{@code NONE} - nothing bound, or a refresh signature failed.</li>
 * </ul>
 *
 * <p>The toolkit's {@code bound} tier is not produced by this library. A stored
 * {@code bound} value reads as {@code NONE}, so a session registered against an
 * older release is demoted rather than trusted.
 */
public enum ProtectionTier {
    DBSC("dbsc"),
    NONE("none");

    private final String wireValue;

    ProtectionTier(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static ProtectionTier fromWire(String value) {
        if (value == null) {
            return NONE;
        }
        return switch (value) {
            case "dbsc" -> DBSC;
            default -> NONE;
        };
    }
}
