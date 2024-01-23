package dzt.smartcps.certificate;

public enum CardSchemes {
    VISA("VISA"),
    MASTERCARD("MASTERCARD"),
    UPI("UPI");

    private final String value;

    CardSchemes(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static CardSchemes fromValue(String value) {
        for (CardSchemes scheme : CardSchemes.values()) {
            if (scheme.value.equals(value)) {
                return scheme;
            }
        }
        throw new IllegalArgumentException("Unknown CardScheme value: " + value);
    }
}

