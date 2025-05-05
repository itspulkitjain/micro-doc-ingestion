package com.pj.docis.service;

import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.sax.BodyContentHandler;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

@Service
public class ApacheTikaTextExtractionService implements TextExtractionService {
    private final AutoDetectParser parser = new AutoDetectParser();
    private final ParseContext context = new ParseContext(); // Reusable context

    @Override
    public String extractText(InputStream inputStream, String mimeType) throws IOException {
        if (inputStream == null) {
            return "";
        }
        Metadata metadata = new Metadata();
        BodyContentHandler handler = new BodyContentHandler(10 * 1024 * 1024);
        try {
            if (mimeType != null && !mimeType.isEmpty()) {
                metadata.set(Metadata.CONTENT_TYPE, mimeType);
            }
            parser.parse(inputStream, handler, metadata, context);
            return handler.toString();
        } catch (Exception e) {
            System.err.println("Error extracting text from document: " + e.getMessage());
            return "";
        }
    }

    @Override
    public String extractText(byte[] content, String mimeType) throws IOException {
        if (content == null || content.length == 0) {
            return "";
        }
        try (InputStream is = new ByteArrayInputStream(content)) {
            return extractText(is, mimeType);
        }
    }

}
