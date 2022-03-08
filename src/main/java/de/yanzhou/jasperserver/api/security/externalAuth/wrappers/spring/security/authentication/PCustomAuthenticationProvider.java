package de.yanzhou.jasperserver.api.security.externalAuth.wrappers.spring.security.authentication;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;

import com.jaspersoft.jasperserver.api.common.crypto.PasswordCipherer;
import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalUserDetails;

/**
 * Custom AuthenticationProvider by using JDBC authentication method.
 */
public class PCustomAuthenticationProvider implements AuthenticationProvider {

    public static final Logger logger = LogManager.getLogger(PCustomAuthenticationProvider.class);

    private static final String KEY_DB_DRIVER = "dbDriver";
    private static final String KEY_DB_HOST = "dbHost";
    private static final String KEY_DB_PORT = "dbPort";
    private static final String KEY_DB_NAME = "dbName";

    private String dbUserNameAttr = "dbusername";
    private String dbUserPasswordAttr = "dbpassword";
    private String dbNameAttr = "dbname";
    private String dbHostAttr = "dbhost";
    private String dbPortAttr = "dbport";

    /**
     * Attempts to authenticate the passed {@link Authentication} object through JDBC.
     *
     * @param authentication the authentication request object.
     *
     * @return a fully authenticated object including credentials.
     *
     * @throws AuthenticationException if authentication fails.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        boolean isAuthenticated = false;
        String username = "";
        String password = "";
        String dbName = "";
        ExternalUserDetails externalUserDetails = null;

        // if the username contains "@", then the string will be split to retrieve the real username before "@"
        // and the database name after "@".
        if (authentication.getName().contains("@")) {
            username = authentication.getName().substring(0 , authentication.getName().indexOf("@"));
            dbName = authentication.getName().substring(authentication.getName().indexOf("@") + 1);
            password = authentication.getCredentials().toString();
            isAuthenticated = isDbInfoValid(dbName, username, password);
        }

        if (isAuthenticated) {
            externalUserDetails = new ExternalUserDetails(authentication.getName(), password, AuthorityUtils.NO_AUTHORITIES);
            Map<String, String> dbCredentialMap = new HashMap<String, String>();
            dbCredentialMap.put(getDbUserNameAttr(), username);
            PasswordCipherer ciph = PasswordCipherer.getInstance();
            String encrPw = ciph.encryptSecureAttribute(password);
            dbCredentialMap.put(getDbUserPasswordAttr(), encrPw);
            dbCredentialMap.put(getDbNameAttr(), getDbInfoFromPropertiesFile(dbName).get(KEY_DB_NAME));
            dbCredentialMap.put(getDbHostAttr(), getDbInfoFromPropertiesFile(dbName).get(KEY_DB_HOST));
            dbCredentialMap.put(getDbPortAttr(), getDbInfoFromPropertiesFile(dbName).get(KEY_DB_PORT));
            externalUserDetails.getAdditionalDetailsMap().put(ExternalUserDetails.PROFILE_ATTRIBUTES_ADDITIONAL_MAP_KEY, dbCredentialMap);
        }
        /*
         *  Example for adding roles:
         *  List<SimpleGrantedAuthority> authorities = new ArrayList<>();
         *  authorities.add(new SimpleGrantedAuthority("EXT"));
         */
        return isAuthenticated ?
                new UsernamePasswordAuthenticationToken(externalUserDetails, password, AuthorityUtils.NO_AUTHORITIES) : null;
    }

    /**
     * Checks the connectivity of a database.
     *
     * @param dbName the name of the database.
     * @param username the username of the database.
     * @param password the password of the database.
     * @return true if the database can be connected.
     */
    private boolean isDbInfoValid(String dbName,String username, String password) {
        boolean isAuthenticated = false;
        Map<String, String> dbInfoMap = getDbInfoFromPropertiesFile(dbName);
        if (!dbInfoMap.isEmpty()) {
            String dbDriver = dbInfoMap.get(KEY_DB_DRIVER);
            String dbHost = dbInfoMap.get(KEY_DB_HOST);
            String dbPort = dbInfoMap.get(KEY_DB_PORT);
            String dbNameFromProperties = dbInfoMap.get(KEY_DB_NAME);
            Connection conn = null;
            try {
                String connectSymbol = dbDriver.toLowerCase().contains("oracle") ? ":@" : "://";
                String dbUrl = dbDriver + connectSymbol + dbHost + ":" + dbPort + "/" + dbNameFromProperties;
                logger.debug("Try to connect to DB [ " + dbUrl + " ], username [ " + username + " ] ");
                conn = DriverManager.getConnection(dbUrl, username, password);
                isAuthenticated = true;
            } catch (SQLException e) {
                logger.error("Can not connect to the database." + e.getMessage(), e.getCause());
            } finally {
                if (conn != null ) {
                    try {
                        conn.close();
                    } catch (SQLException e) {
                        logger.error("Can not close the database." + e.getMessage(), e.getCause());
                    }
                }
            }
        } else {
            logger.error("Can not find the information of DB: " + dbName + ", please check db.properties file.");
        }
        return isAuthenticated;
    }

    /**
     * Gets the information of db.driver, db.{dbName}.host and db.{dbName}.port from the db.properties file.
     * The path of db.properties is C:\Jaspersoft\jasperreports-server-cp-7.8.0\apache-tomcat\conf\db.properties
     *
     * @param dbName the given database name.
     *
     * @return a Map contains the the information of db.driver, db.{dbName}.serverName and db.{dbName}.serverPort.
     */
    private Map<String, String> getDbInfoFromPropertiesFile(String dbName){
        Map<String, String> dbInfoMap = new HashMap<String,String>();
        InputStream in = null;
        try {
            Properties props = new Properties();
            in = new FileInputStream("conf/db.properties");
            props.load(in);
            dbInfoMap.put(KEY_DB_DRIVER, props.getProperty("db.driver"));
            dbInfoMap.put(KEY_DB_HOST, props.getProperty("db." + dbName.toLowerCase() + ".host"));
            dbInfoMap.put(KEY_DB_PORT, props.getProperty("db." + dbName.toLowerCase() + ".port"));
            dbInfoMap.put(KEY_DB_NAME, props.getProperty("db." + dbName.toLowerCase() + ".name"));
        } catch (FileNotFoundException e) {
            logger.error("File db.properties not found." + e.getMessage(), e.getCause());
        } catch (IOException e) {
            logger.error("File db.properties can not be read." + e.getMessage(), e.getCause());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("File db.properties can not be closed." + e.getMessage(), e.getCause());
                }
            }
        }
        return dbInfoMap;
    }

    @Override
    public boolean supports(Class<?> arg0) {
        // TODO Auto-generated method stub
        return true;
    }

    public String getDbNameAttr() {
        return dbNameAttr;
    }

    public void setDbNameAttr(String dbNameAttr) {
        this.dbNameAttr = dbNameAttr;
    }

    public String getDbUserNameAttr() {
        return dbUserNameAttr;
    }

    public void setDbUserNameAttr(String dbUserNameAttr) {
        this.dbUserNameAttr = dbUserNameAttr;
    }

    public String getDbUserPasswordAttr() {
        return dbUserPasswordAttr;
    }

    public void setDbUserPasswordAttr(String dbUserPasswordAttr) {
        this.dbUserPasswordAttr = dbUserPasswordAttr;
    }

    public String getDbHostAttr() {
        return dbHostAttr;
    }

    public void setDbHostAttr(String dbHostAttr) {
        this.dbHostAttr = dbHostAttr;
    }

    public String getDbPortAttr() {
        return dbPortAttr;
    }

    public void setDbPortAttr(String dbPortAttr) {
        this.dbPortAttr = dbPortAttr;
    }

}