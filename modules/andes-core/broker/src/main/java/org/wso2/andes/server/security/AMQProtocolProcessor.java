package org.wso2.andes.server.security;

/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import org.wso2.andes.configuration.AndesConfigurationManager;
import org.wso2.andes.configuration.enums.AMQPAuthorizationPermissionLevel;
import org.wso2.andes.configuration.enums.AMQPUserAuthenticationScheme;
import org.wso2.andes.configuration.enums.AMQPUserAuthorizationScheme;
import org.wso2.andes.configuration.enums.AndesConfiguration;
import org.wso2.andes.server.exception.AMQPInitializationException;
import org.wso2.andes.server.exception.AMQPTopicSubscriptionException;
import org.wso2.andes.server.security.access.amqp.IAuthenticator;
import org.wso2.andes.server.security.auth.amqp.IAuthorizer;

//import static org.wso2.andes.configuration.enums.AndesConfiguration.TRANSPORTS_AMQP_USER_AUTHENTICATION;
import static org.wso2.andes.configuration.enums.AndesConfiguration.TRANSPORTS_AMQP_USER_AUTHORIZATION;

public class AMQProtocolProcessor {

    private boolean isAuthenticationRequired;
    private IAuthenticator m_authenticator;

    private boolean isAuthorizationRequired;
    private IAuthorizer m_authorizer;

    //TODO: Use this method on server startup
    public void init(){
        String authenticatorClassName = null;
//        try {
//            authenticatorClassName = AndesConfigurationManager.readValue(AndesConfiguration.TRANSPORTS_AMQP_USER_AUTHENTICATOR_CLASS);
//            Class <? extends IAuthenticator> authenticatorClass = Class.forName(authenticatorClassName).asSubclass(IAuthenticator.class);
//            m_authenticator = authenticatorClass.newInstance();

//            isAuthenticationRequired = AndesConfigurationManager.readValue(TRANSPORTS_AMQP_USER_AUTHENTICATION) ==
//                    AMQPUserAuthenticationScheme.REQUIRED;
            isAuthorizationRequired = AndesConfigurationManager.readValue(TRANSPORTS_AMQP_USER_AUTHORIZATION) ==
                    AMQPUserAuthorizationScheme.REQUIRED;

            if(isAuthorizationRequired){
                String authorizerClassName = AndesConfigurationManager.readValue(
                        AndesConfiguration.TRANSPORTS_AMQP_USER_AUTHORIZATION_CLASS);
                try {
                    Class authorizeClass = Class.forName(authorizerClassName).asSubclass(IAuthorizer.class);
                    m_authorizer = (IAuthorizer) authorizeClass.newInstance();
                } catch (ClassNotFoundException e) {
                    throw new AMQPInitializationException("Unable to find the class authorizer: " + authorizerClassName, e);
                } catch (InstantiationException e) {
                    throw new AMQPInitializationException("Unable to create an instance of :" + authorizerClassName, e);
                } catch (IllegalAccessException e) {
                    throw new AMQPInitializationException("Access of the instance in not allowed.", e);
                }
            }
//        } catch (ClassNotFoundException e) {
//            throw new RuntimeException("unable to find the class authenticator: " +  authenticatorClassName, e);
//        } catch (InstantiationException e) {
//            throw new RuntimeException("unable to create an instance of :" + authenticatorClassName, e);
//        } catch (IllegalAccessException e) {
//            throw new RuntimeException("unable to create an instance of :", e);
//        }
    }

    public boolean processTopic(String topic, String username, AMQPAuthorizationPermissionLevel permissionLevel) throws AMQPTopicSubscriptionException{
        if(isAuthorizationRequired && m_authorizer != null){
            boolean authorized = m_authorizer.isAuthorizedForTopic(topic, username, permissionLevel);
            return authorized;
        }else {
            return true;
        }
    }
}
