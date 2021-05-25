package com.exemple.authorization.application.detail;

import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.fasterxml.jackson.databind.JsonNode;

public interface ApplicationDetailService {

    void put(String application, JsonNode detail);

    ApplicationDetail get(String application);

}