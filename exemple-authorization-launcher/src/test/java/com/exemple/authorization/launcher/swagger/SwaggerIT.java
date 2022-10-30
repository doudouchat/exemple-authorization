package com.exemple.authorization.launcher.swagger;

import org.junit.platform.suite.api.ConfigurationParameter;
import org.junit.platform.suite.api.IncludeEngines;
import org.junit.platform.suite.api.SelectClasspathResource;
import org.junit.platform.suite.api.Suite;

import io.cucumber.junit.platform.engine.Constants;

@Suite
@IncludeEngines("cucumber")
@SelectClasspathResource("feature/swagger")
@ConfigurationParameter(key = Constants.GLUE_PROPERTY_NAME, value = "com.exemple.authorization.launcher.core, "
        + "com.exemple.authorization.launcher.swagger")
class SwaggerIT {

}
