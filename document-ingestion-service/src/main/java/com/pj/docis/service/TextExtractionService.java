package com.pj.docis.service;

import java.io.IOException;
import java.io.InputStream;

public interface TextExtractionService {

    String extractText(InputStream inputStream, String mimeType) throws IOException;

    String extractText(byte[] content, String mimeType) throws IOException;

}
