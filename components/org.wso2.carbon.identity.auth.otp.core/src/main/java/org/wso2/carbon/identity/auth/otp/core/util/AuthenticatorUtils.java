/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.auth.otp.core.util;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;

import javax.servlet.http.HttpServletRequest;

import java.util.Map;

import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MULTI_OPTION_URI_PARAM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY;

/**
 * Utility functions for the authenticator.
 */
public class AuthenticatorUtils {

    private static final Log LOG = LogFactory.getLog(AuthenticatorUtils.class);
    /**
     * Get the multi option URI query param.
     *
     * @param request HttpServletRequest.
     * @return Query parameter for the multi option URI.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    public static String getMultiOptionURIQueryString(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter("multiOptionURI");
            multiOptionURI = multiOptionURI != null ? MULTI_OPTION_URI_PARAM +
                    Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }

    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws
            AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = AuthenticatorDataHolder
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY,
                                    AuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    FAILED_LOGIN_ATTEMPTS_PROPERTY,
                                    ACCOUNT_UNLOCK_TIME_PROPERTY
                            }, tenantDomain);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while retrieving account lock connector " +
                    "configuration for tenant : " +  tenantDomain, e);
        }
        return connectorConfigs;
    }

    /**
     * Get the maximum allowed retry attempts limit from the runtime parameters.
     * If not found or invalid, return -1.
     *
     * @param runtimeParams Runtime parameters map.
     * @return Maximum allowed retry attempts limit.
     */
    public static int getMaximumAllowedRetryAttemptsLimit(Map<String, String> runtimeParams) {

        if (runtimeParams != null && runtimeParams.get(AuthenticatorConstants.ALLOWED_RETRY_COUNT) != null) {
            try {
                return Integer.parseInt(runtimeParams.get(AuthenticatorConstants.ALLOWED_RETRY_COUNT));
            } catch (NumberFormatException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Invalid value provided for maximum allowed retry attempts limit. " +
                            "Falling back to default value of 5.", e);
                }
                return -1;
            }
        }
        return -1;
    }

    /**
    * Get the maximum allowed resend attempts limit from the runtime parameters.
    * If not found or invalid, return the default value of 5.
    *
    * @param runtimeParams Runtime parameters map.
    * @return Maximum allowed resend attempts limit.
    */
    public static int getMaximumAllowedResendAttemptsLimit(Map<String, String> runtimeParams) {

        if (runtimeParams != null && runtimeParams.get(AuthenticatorConstants.ALLOWED_RESEND_COUNT) != null) {
            try {
                return Integer.parseInt(runtimeParams.get(AuthenticatorConstants.ALLOWED_RESEND_COUNT));
            } catch (NumberFormatException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Invalid value provided for maximum allowed resend attempts limit. " +
                            "Falling back to default value of 5.", e);
                }
                return AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS;
            }
        }
        return AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS;
    }
}

