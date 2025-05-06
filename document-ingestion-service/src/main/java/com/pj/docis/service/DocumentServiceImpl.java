package com.pj.docis.service;

import com.pj.docis.dto.DocumentMapper;
import com.pj.docis.dto.DocumentRequest;
import com.pj.docis.dto.DocumentResponse;
import com.pj.docis.entity.DocumentElasticsearch;
import com.pj.docis.entity.DocumentEntity;
import com.pj.docis.repository.DocumentElasticsearchRepository;
import com.pj.docis.repository.DocumentRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.data.elasticsearch.core.query.StringQuery;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class DocumentServiceImpl implements DocumentService {

    @Autowired
    private DocumentRepo documentRepo;

    @Autowired
    private DocumentElasticsearchRepository elasticsearchRepository;

    @Autowired
    private TextExtractionService textExtractionService;

    @Autowired
    private ElasticsearchOperations elasticsearchOperations;


    @Override
    @Transactional
    public DocumentResponse uploadDocument(DocumentRequest request, MultipartFile file) {
        try {
            DocumentEntity document = DocumentMapper.mapper.toEntity(request);
            /**
             * @implNote storing contents to DB
             */
            document.setContent(file.getBytes());
            /**
             * @implNote need to store file to AWS
             */
            String fileUrl = awsStoreFile(file); // TODO: Implement this method
            document.setFileUrl(fileUrl);
            document.setAuthor("U01");
            document = documentRepo.saveAndFlush(document);

            DocumentElasticsearch elasticDocument = DocumentMapper.mapper.toElasticsearchDocument(document);
            String extractedText = "";
            try {
                extractedText = textExtractionService.extractText(document.getContent(), document.getMimeType());
            } catch (IOException e) {
                System.err.println("Failed to extract text for document ID " + document.getId() + ": " + e.getMessage());
            }
            elasticDocument.setExtractedContent(extractedText);
            elasticsearchRepository.save(elasticDocument);
            return getDocumentResponse(document);
        } catch (IOException e) {
            throw new RuntimeException("Error uploading document: " + e.getMessage(), e);
        }
    }

    private static DocumentResponse getDocumentResponse(DocumentEntity document) {
        DocumentResponse response = new DocumentResponse();
        if(document!=null)
            response.setDocument(DocumentMapper.mapper.toJson(document));
        return response;
    }

    private static DocumentResponse getDocumentResponse(List<DocumentEntity> documents) {
        DocumentResponse response = new DocumentResponse();
        if(documents!=null)
            response.setDocuments(DocumentMapper.mapper.toJsons(documents));
        return response;
    }

    private String awsStoreFile(MultipartFile file) {
        //TODO: Store to AWS
        /**
         * @implNote for example returning sameple string
         */
        return "https://www.pj.docs.com/" + UUID.randomUUID().toString() + "-" + file.getOriginalFilename();
    }

    @Override
    public DocumentResponse getDocumentById(Long id) {
        return getDocumentResponse(documentRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Document not found with id: " + id)));
    }

    @Override
    public DocumentResponse getAllDocuments(Pageable pageable) {
        return getDocumentResponse(documentRepo.findAll(pageable).getContent());
    }

    @Override
    public DocumentEntity getDocumentContent(Long id) {
        return documentRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Document not found with id: " + id));
    }

    @Override
    public List<DocumentElasticsearch> simpleSearchDocuments(String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) { return List.of(); }
        return elasticsearchRepository.findByTitleOrFileNameOrExtractedContentOrAuthorOrDescriptionContaining(
                keyword, keyword, keyword, keyword, keyword);
    }

    @Override
    public List<DocumentElasticsearch> advancedSearchDocuments(String query) {
        if (query == null || query.trim().isEmpty()) {
            return List.of();
        }

        String queryString = String.format(
                """
                {
                  "multi_match": {
                    "query": "%s",
                    "fields": ["title^3", "fileName", "extractedContent^5", "author", "description", "metadataString"],
                    "fuzziness": "AUTO"
                  }
                }
                """, query.replace("\"", "\\\""));

        StringQuery stringQuery = new StringQuery(queryString);
        SearchHits<DocumentElasticsearch> searchHits = elasticsearchOperations.search(stringQuery, DocumentElasticsearch.class);
        return searchHits.stream()
                .map(SearchHit::getContent)
                .collect(Collectors.toList());
    }
}
