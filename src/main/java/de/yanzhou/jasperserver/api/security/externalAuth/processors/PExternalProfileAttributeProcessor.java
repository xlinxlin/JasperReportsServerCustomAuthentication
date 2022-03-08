package de.yanzhou.jasperserver.api.security.externalAuth.processors;

import static com.jaspersoft.jasperserver.api.security.externalAuth.processors.ProcessorData.Key.EXTERNAL_AUTH_DETAILS;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.userdetails.UserDetails;

import com.jaspersoft.jasperserver.api.metadata.user.service.ProfileAttributeService;
import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalUserDetails;
import com.jaspersoft.jasperserver.api.security.externalAuth.processors.AbstractExternalUserProcessor;
import com.jaspersoft.jasperserver.api.security.externalAuth.processors.ProcessorData;

public class PExternalProfileAttributeProcessor extends AbstractExternalUserProcessor {

    private static Logger logger = LogManager.getLogger(PExternalProfileAttributeProcessor.class);

    public PExternalProfileAttributeProcessor()	{
        super();
    }

    @SuppressWarnings("unchecked")
    @Override
    public void process() {
        ProcessorData processorData = ProcessorData.getInstance();
        UserDetails externalUserDetails = (UserDetails) processorData.getData(EXTERNAL_AUTH_DETAILS);

        logger.debug("Method process, externalUserDetails class type=" + externalUserDetails.getClass());
        if (externalUserDetails instanceof ExternalUserDetails) {
            final ProfileAttributeService profileAttributeService = getProfileAttributeService();

            Map<String, Object> additionalDetailMap = ((ExternalUserDetails) externalUserDetails).getAdditionalDetailsMap();
            Map<String, String> dbCredentialMap = (Map<String, String>) additionalDetailMap.get(ExternalUserDetails.PROFILE_ATTRIBUTES_ADDITIONAL_MAP_KEY);
            logger.debug("Method process, additionalDetailMap=" + dbCredentialMap);

            for (Map.Entry<String, String> pair : dbCredentialMap.entrySet()) {
                logger.debug("Method process, setting user profile attribute: " + pair.getKey() + ", value: " + pair.getValue());
                profileAttributeService.setCurrentUserPreferenceValue(pair.getKey(), pair.getValue());
            }
        }
    }
}