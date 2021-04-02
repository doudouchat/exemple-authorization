package com.exemple.authorization.application.detail;

import com.exemple.authorization.application.common.model.ApplicationDetail;

public interface ApplicationDetailService {

    void put(String application, ApplicationDetail detail);

    ApplicationDetail get(String application);

}
