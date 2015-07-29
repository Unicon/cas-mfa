package net.unicon.cas.mfa.authentication.loc;

/**
 * Keeps track of location of an authentication object.
 * @author Misagh Moayyed
 */
public final class AuthenticationLocation {
    private final String ipAddress;
    private final String countryCode;
    private final String countryName;
    private final String regionName;
    private final String cityName;
    private final String zipCode;
    private final String latitude;
    private final String longitude;
    private final String timeZone;

    /**
     * Instantiates a new Authentication location.
     *
     * @param ipAddress the ip address
     * @param countryCode the country code
     * @param countryName the country name
     * @param regionName the region name
     * @param cityName the city name
     * @param zipCode the zip code
     * @param latitude the latitude
     * @param longitude the longitude
     * @param timeZone the time zone
     */
    public AuthenticationLocation(final String ipAddress,
                                  final String countryCode,
                                  final String countryName,
                                  final String regionName,
                                  final String cityName,
                                  final String zipCode,
                                  final String latitude,
                                  final String longitude,
                                  final String timeZone) {
        this.ipAddress = ipAddress;
        this.countryCode = countryCode;
        this.countryName = countryName;
        this.regionName = regionName;
        this.cityName = cityName;
        this.zipCode = zipCode;
        this.latitude = latitude;
        this.longitude = longitude;
        this.timeZone = timeZone;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public String getCountryName() {
        return countryName;
    }

    public String getRegionName() {
        return regionName;
    }

    public String getCityName() {
        return cityName;
    }

    public String getZipCode() {
        return zipCode;
    }

    public String getLatitude() {
        return latitude;
    }

    public String getLongitude() {
        return longitude;
    }

    public String getTimeZone() {
        return timeZone;
    }
}
