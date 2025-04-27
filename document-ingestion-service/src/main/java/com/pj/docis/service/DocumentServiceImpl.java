package com.pj.docis.service;

import com.pj.docis.dto.DocumentMapper;
import com.pj.docis.dto.DocumentRequest;
import com.pj.docis.dto.DocumentResponse;
import com.pj.docis.entity.DocumentEntity;
import com.pj.docis.repository.DocumentRepo;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Service
public class DocumentServiceImpl implements DocumentService {

    @Autowired
    private DocumentRepo documentRepo;

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
            String fileUrl = awsStoreFile(file); // Implement this method
            document.setFileUrl(fileUrl);
            document.setAuthor("U01");
            document = documentRepo.saveAndFlush(document);
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
}
