package com.exemple.authorization.application.detail;

import java.util.Optional;

import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.fasterxml.jackson.databind.JsonNode;

public interface ApplicationDetailService {

    void put(String application, JsonNode detail);

    Optional<ApplicationDetail> get(String application);

}
