package com.pj.docis.dto;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;

import java.time.ZonedDateTime;

@Data
public class DocumentRequest {

    @NotBlank
    private String title;
    @NotBlank
    private String fileName;
    @NotBlank
    private String mimeType;
    private String source;
    private String description;

}
