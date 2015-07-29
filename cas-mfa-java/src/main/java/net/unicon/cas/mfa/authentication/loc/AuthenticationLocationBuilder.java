package net.unicon.cas.mfa.authentication.loc;

/**
 * Builds an authentication location.
 * @author Misagh Moayyed
 */
public final class AuthenticationLocationBuilder {
    /**
     * The Ip address.
     */
    private String ipAddress;
    /**
     * The Country code.
     */
    private String countryCode;
    /**
     * The Country name.
     */
    private String countryName;
    /**
     * The Region name.
     */
    private String regionName;
    /**
     * The City name.
     */
    private String cityName;
    /**
     * The Zip code.
     */
    private String zipCode;
    /**
     * The Latitude.
     */
    private String latitude;
    /**
     * The Longitude.
     */
    private String longitude;
    /**
     * The Time zone.
     */
    private String timeZone;

    /**
     * Sets ip address.
     *
     * @param ipAddress the ip address
     * @return the ip address
     */
    public AuthenticationLocationBuilder setIpAddress(final String ipAddress) {
        this.ipAddress = ipAddress;
        return this;
    }

    /**
     * Sets country code.
     *
     * @param countryCode the country code
     * @return the country code
     */
    public AuthenticationLocationBuilder setCountryCode(final String countryCode) {
        this.countryCode = countryCode;
        return this;
    }

    /**
     * Sets country name.
     *
     * @param countryName the country name
     * @return the country name
     */
    public AuthenticationLocationBuilder setCountryName(final String countryName) {
        this.countryName = countryName;
        return this;
    }

    /**
     * Sets region name.
     *
     * @param regionName the region name
     * @return the region name
     */
    public AuthenticationLocationBuilder setRegionName(final String regionName) {
        this.regionName = regionName;
        return this;
    }

    /**
     * Sets city name.
     *
     * @param cityName the city name
     * @return the city name
     */
    public AuthenticationLocationBuilder setCityName(final String cityName) {
        this.cityName = cityName;
        return this;
    }

    /**
     * Sets zip code.
     *
     * @param zipCode the zip code
     * @return the zip code
     */
    public AuthenticationLocationBuilder setZipCode(final String zipCode) {
        this.zipCode = zipCode;
        return this;
    }

    /**
     * Sets latitude.
     *
     * @param latitude the latitude
     * @return the latitude
     */
    public AuthenticationLocationBuilder setLatitude(final String latitude) {
        this.latitude = latitude;
        return this;
    }

    /**
     * Sets longitude.
     *
     * @param longitude the longitude
     * @return the longitude
     */
    public AuthenticationLocationBuilder setLongitude(final String longitude) {
        this.longitude = longitude;
        return this;
    }

    /**
     * Sets time zone.
     *
     * @param timeZone the time zone
     * @return the time zone
     */
    public AuthenticationLocationBuilder setTimeZone(final String timeZone) {
        this.timeZone = timeZone;
        return this;
    }

    /**
     * Create authentication location.
     *
     * @return the authentication location
     */
    public AuthenticationLocation build() {
        return new AuthenticationLocation(ipAddress, countryCode, countryName,
                regionName, cityName, zipCode, latitude, longitude, timeZone);
    }
}
