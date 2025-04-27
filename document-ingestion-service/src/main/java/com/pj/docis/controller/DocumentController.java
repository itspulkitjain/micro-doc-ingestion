package com.pj.docis.controller;

import com.pj.docis.dto.Document;
import com.pj.docis.dto.DocumentRequest;
import com.pj.docis.dto.DocumentResponse;
import com.pj.docis.entity.DocumentEntity;
import com.pj.docis.service.DocumentService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping(value = "/docs")
public class DocumentController {

    @Autowired
    DocumentService documentService;

    @PostMapping(value = "/upload", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<DocumentResponse> uploadDocument(
            @RequestPart @Validated DocumentRequest metadata,
            @RequestPart MultipartFile file) {
        DocumentResponse response = documentService.uploadDocument(metadata, file);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("{id}")
    public ResponseEntity<DocumentResponse> getDocumentById(@PathVariable Long id) {
        DocumentResponse response = documentService.getDocumentById(id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/list")
    public ResponseEntity<DocumentResponse> getAllDocuments(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        DocumentResponse response = documentService.getAllDocuments(PageRequest.of(page, size));
        return ResponseEntity.ok(response);
    }

    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> downloadDocument(@PathVariable Long id) {
        DocumentEntity document = documentService.getDocumentContent(id);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(document.getMimeType()))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + document.getFileName() + "\"")
                .body(document.getContent());
    }

}
