package com.pj.user.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
public class UserResponse {
    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    User user;

    private boolean success;

    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    private  String errorMsg;

    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    private Integer errorCode;
}
