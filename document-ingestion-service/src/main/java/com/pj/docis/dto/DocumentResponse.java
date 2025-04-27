package com.pj.docis.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import jakarta.persistence.Column;
import jakarta.persistence.Lob;
import lombok.Data;

import java.util.List;

@Data
public class DocumentResponse {
    @JsonInclude(value = Include.NON_NULL)
    Document document;
    
    @JsonInclude(value = Include.NON_EMPTY)
    List<Document> documents;
}
