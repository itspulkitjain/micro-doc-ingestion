package com.pj.docis.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.Data;

import java.time.ZonedDateTime;

@Data
public class Document {
        @JsonInclude(Include.NON_NULL)
        private String id;
        @JsonInclude(Include.NON_NULL)
        private String title;
        @JsonInclude(Include.NON_NULL)
        private String fileName;
        @JsonInclude(Include.NON_NULL)
        private String fileUrl;
        @JsonInclude(Include.NON_NULL)
        private String mimeType;
        @JsonInclude(Include.NON_NULL)
        private String author;
        @JsonInclude(Include.NON_NULL)
        private String uploadDate;
        @JsonInclude(Include.NON_NULL)
        private String source;
        @JsonInclude(Include.NON_NULL)
        private String description;
        @JsonInclude(value = Include.NON_NULL)
        private byte[] content;
}
