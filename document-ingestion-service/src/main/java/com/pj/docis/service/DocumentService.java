package com.pj.docis.service;

import com.pj.docis.dto.DocumentRequest;
import com.pj.docis.dto.DocumentResponse;
import com.pj.docis.entity.DocumentElasticsearch;
import com.pj.docis.entity.DocumentEntity;
import jakarta.validation.Valid;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface DocumentService {

    DocumentResponse uploadDocument(@Valid DocumentRequest document, MultipartFile file);

    DocumentResponse getDocumentById(Long id);

    DocumentResponse getAllDocuments(Pageable pageable);

    DocumentEntity getDocumentContent(Long id);

    List<DocumentElasticsearch> simpleSearchDocuments(String keyword);
}
