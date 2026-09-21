package click.yukio.dbsc.crypto;

/**
 * The two algorithms DBSC supports (spec 05).
 */
public enum DbscAlgorithm {
    ES256("ES256"),
    RS256("RS256");

    private final String wireValue;

    DbscAlgorithm(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static DbscAlgorithm fromWire(String value) {
        if (value == null) {
            return null;
        }
        return switch (value) {
            case "ES256" -> ES256;
            case "RS256" -> RS256;
            default -> null;
        };
    }
}
